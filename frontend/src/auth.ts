import './auth.css';
import { el, icon } from './dom';
import { formatMoney } from './format';

interface AuthUser {
  id: string;
  name: string;
  email: string;
  provider: string;
}

interface AuthProvider {
  id: string;
  name: string;
}

interface OrderLine {
  name: string;
  quantity: number;
  unit_price_cents: number;
}

interface MyOrder {
  id: string;
  created_at: string;
  total_cents: number;
  items: OrderLine[];
  billing_status: string;
  invoice_number: string | null;
}

type OrdersState = 'idle' | 'loading' | 'ready' | 'error';

const errorMessages: Record<string, string> = {
  denied: 'Cancelaste el inicio de sesión. Puedes intentarlo de nuevo cuando quieras.',
  state: 'La sesión de inicio expiró o no es válida. Inténtalo de nuevo.',
  exchange_failed: 'No pudimos completar el inicio de sesión con el proveedor. Inténtalo de nuevo.',
  profile_failed: 'No pudimos leer tu perfil del proveedor. Inténtalo de nuevo.',
  no_email: 'El proveedor no nos entregó un correo. Prueba con otro proveedor.',
  email_unverified: 'Tu correo en ese proveedor no está verificado. Verifícalo o usa otro proveedor.'
};

let user: AuthUser | null = null;
let providers: AuthProvider[] = [];
let loaded = false;
let errorText = '';
let busy = false;
let orders: MyOrder[] = [];
let ordersState: OrdersState = 'idle';
let ordersToken = 0;

let navButton: HTMLButtonElement;
let dialog: HTMLDialogElement;
let body: HTMLElement;
let lastFocused: HTMLElement | null = null;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function getJson(path: string): Promise<unknown> {
  const response = await fetch(path, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    cache: 'no-store',
    credentials: 'same-origin'
  });
  if (!response.ok) {
    throw new Error('request failed');
  }
  return (await response.json()) as unknown;
}

function parseUser(value: unknown): AuthUser | null {
  if (!isRecord(value) || !isRecord(value.user)) {
    return null;
  }
  const { id, name, email, provider } = value.user;
  if (
    typeof id !== 'string' ||
    typeof name !== 'string' ||
    typeof email !== 'string' ||
    typeof provider !== 'string'
  ) {
    return null;
  }
  return { id, name, email, provider };
}

function parseProviders(value: unknown): AuthProvider[] {
  if (!isRecord(value) || !Array.isArray(value.providers)) {
    return [];
  }
  const list: AuthProvider[] = [];
  for (const entry of value.providers) {
    if (isRecord(entry) && typeof entry.id === 'string' && typeof entry.name === 'string') {
      if (/^[a-z0-9_-]{1,32}$/.test(entry.id)) {
        list.push({ id: entry.id, name: entry.name });
      }
    }
  }
  return list;
}

function parseOrders(value: unknown): MyOrder[] {
  if (!isRecord(value) || !Array.isArray(value.orders)) {
    throw new Error('invalid orders');
  }
  const list: MyOrder[] = [];
  for (const entry of value.orders) {
    if (
      !isRecord(entry) ||
      typeof entry.id !== 'string' ||
      typeof entry.created_at !== 'string' ||
      typeof entry.total_cents !== 'number' ||
      !Array.isArray(entry.items)
    ) {
      continue;
    }
    const items: OrderLine[] = [];
    for (const raw of entry.items) {
      if (
        isRecord(raw) &&
        typeof raw.name === 'string' &&
        typeof raw.quantity === 'number' &&
        typeof raw.unit_price_cents === 'number'
      ) {
        items.push({ name: raw.name, quantity: raw.quantity, unit_price_cents: raw.unit_price_cents });
      }
    }
    list.push({
      id: entry.id,
      created_at: entry.created_at,
      total_cents: entry.total_cents,
      items,
      billing_status: typeof entry.billing_status === 'string' ? entry.billing_status : 'not_requested',
      invoice_number:
        typeof entry.invoice_number === 'string' && entry.invoice_number.length > 0
          ? entry.invoice_number
          : null
    });
  }
  return list;
}

async function loadOrders(): Promise<void> {
  if (!user) {
    return;
  }
  const token = ++ordersToken;
  ordersState = 'loading';
  renderBody();
  try {
    const payload = await getJson('/api/v1/auth/me/orders');
    if (token !== ordersToken) {
      return;
    }
    orders = parseOrders(payload);
    ordersState = 'ready';
  } catch {
    if (token !== ordersToken) {
      return;
    }
    ordersState = 'error';
  }
  renderBody();
}

function invoiceLabel(order: MyOrder): string {
  if (order.billing_status === 'issued') {
    return order.invoice_number ? `Comprobante ${order.invoice_number}` : 'Comprobante emitido';
  }
  if (order.billing_status === 'pending') {
    return 'Comprobante en proceso';
  }
  if (order.billing_status === 'failed') {
    return 'Comprobante con error';
  }
  return 'Sin comprobante';
}

function formatDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString('es-PE', { dateStyle: 'medium', timeStyle: 'short' });
}

function orderNode(order: MyOrder): HTMLElement {
  const badge = el(
    'span',
    { class: `auth-badge auth-badge-${order.billing_status}` },
    invoiceLabel(order)
  );
  const lines = el('ul', { class: 'auth-order-lines' });
  for (const item of order.items) {
    lines.append(
      el(
        'li',
        {},
        `${item.quantity} × ${item.name} · ${formatMoney(item.unit_price_cents * item.quantity)}`
      )
    );
  }
  return el(
    'details',
    { class: 'auth-order' },
    el(
      'summary',
      {},
      el('span', { class: 'auth-order-date' }, formatDate(order.created_at)),
      el('strong', { class: 'auth-order-total' }, formatMoney(order.total_cents)),
      badge
    ),
    el(
      'div',
      { class: 'auth-order-detail' },
      el('p', { class: 'auth-order-id' }, `Pedido ${order.id}`),
      lines,
      el('p', { class: 'auth-order-invoice' }, invoiceLabel(order))
    )
  );
}

function ordersNode(): Node {
  if (ordersState === 'loading' || ordersState === 'idle') {
    return el('p', { class: 'panel-intro' }, 'Cargando tus pedidos…');
  }
  if (ordersState === 'error') {
    return el('p', { class: 'field-error auth-error', role: 'alert' }, 'No pudimos cargar tus pedidos. Inténtalo de nuevo.');
  }
  if (orders.length === 0) {
    return el(
      'p',
      { class: 'panel-intro' },
      'Aún no tienes pedidos con esta cuenta. Los que hagas con la sesión iniciada aparecerán aquí con su comprobante.'
    );
  }
  const list = el('div', { class: 'auth-orders' });
  for (const order of orders) {
    list.append(orderNode(order));
  }
  return list;
}

function firstName(name: string): string {
  const first = name.trim().split(/\s+/)[0] ?? '';
  return first.length > 0 ? first : 'Cuenta';
}

function providerLabel(id: string): string {
  return providers.find((item) => item.id === id)?.name ?? id;
}

function syncNavButton(): void {
  if (!loaded || (user === null && providers.length === 0)) {
    navButton.hidden = true;
    return;
  }
  navButton.hidden = false;
  navButton.replaceChildren();
  if (user) {
    navButton.append(el('span', { class: 'auth-avatar', 'aria-hidden': 'true' }, firstName(user.name).charAt(0).toUpperCase()));
    navButton.append(el('span', { class: 'auth-nav-name' }, firstName(user.name)));
    navButton.setAttribute('aria-label', `Cuenta de ${user.name}`);
  } else {
    navButton.append('Ingresar');
    navButton.setAttribute('aria-label', 'Ingresar a tu cuenta');
  }
}

function renderBody(): void {
  const nodes: Node[] = [];

  if (errorText.length > 0) {
    nodes.push(el('p', { class: 'field-error auth-error', role: 'alert' }, errorText));
  }

  if (user) {
    const logoutButton = el(
      'button',
      { type: 'button', class: 'button button-secondary button-full', 'data-auth-logout': '' },
      busy ? 'Cerrando sesión…' : 'Cerrar sesión'
    );
    logoutButton.disabled = busy;
    const refreshButton = el(
      'button',
      { type: 'button', class: 'button button-secondary button-full auth-refresh', 'data-auth-refresh': '' },
      'Actualizar pedidos'
    );
    refreshButton.disabled = ordersState === 'loading';
    nodes.push(
      el('h3', { class: 'section-label' }, 'Tu cuenta'),
      el(
        'dl',
        { class: 'auth-account' },
        el('dt', {}, 'Nombre'),
        el('dd', {}, user.name),
        el('dt', {}, 'Correo'),
        el('dd', {}, user.email),
        el('dt', {}, 'Ingresaste con'),
        el('dd', {}, providerLabel(user.provider))
      ),
      el('h3', { class: 'section-label' }, 'Mis pedidos y comprobantes'),
      ordersNode(),
      refreshButton,
      logoutButton
    );
  } else {
    nodes.push(
      el('h3', { class: 'section-label' }, 'Ingresar'),
      el(
        'p',
        { class: 'panel-intro' },
        'Entra con tu cuenta para guardar tu sesión. Comprar sigue funcionando sin cuenta.'
      )
    );
    const list = el('div', { class: 'auth-providers' });
    for (const provider of providers) {
      const link = el(
        'a',
        {
          class: 'button button-secondary button-full',
          href: `/api/v1/auth/${encodeURIComponent(provider.id)}/login`
        },
        `Continuar con ${provider.name}`
      );
      list.append(link);
    }
    nodes.push(list);
    nodes.push(
      el(
        'p',
        { class: 'field-hint' },
        'Solo usamos tu nombre y correo para identificarte. Esta es una tienda de demostración.'
      )
    );
  }

  body.replaceChildren(...nodes);
}

function openDialog(): void {
  if (dialog.open) {
    return;
  }
  lastFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  renderBody();
  if (user) {
    void loadOrders();
  }
  dialog.showModal();
  document.documentElement.classList.add('has-dialog');
  window.requestAnimationFrame(() => {
    const target = body.querySelector<HTMLElement>('a.button, button.button');
    (target ?? dialog.querySelector<HTMLElement>('.icon-button'))?.focus();
  });
}

function onDialogClose(): void {
  document.documentElement.classList.remove('has-dialog');
  errorText = '';
  const target = lastFocused;
  lastFocused = null;
  if (target?.isConnected) {
    target.focus();
  }
}

async function logout(): Promise<void> {
  if (busy) {
    return;
  }
  busy = true;
  errorText = '';
  renderBody();
  try {
    const response = await fetch('/api/v1/auth/logout', {
      method: 'POST',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
      credentials: 'same-origin'
    });
    if (!response.ok) {
      throw new Error('logout failed');
    }
    user = null;
    orders = [];
    ordersState = 'idle';
    ordersToken += 1;
    busy = false;
    syncNavButton();
    dialog.close();
  } catch {
    busy = false;
    errorText = 'No pudimos cerrar la sesión. Inténtalo de nuevo.';
    renderBody();
  }
}

function buildDialog(): void {
  const title = el('h2', { class: 'panel-title', id: 'auth-title', tabindex: '-1' }, 'Cuenta');
  const close = el('button', { type: 'button', class: 'icon-button', 'aria-label': 'Cerrar' });
  close.append(icon('close'));
  body = el('div', { class: 'panel-body' });
  dialog = el(
    'dialog',
    { class: 'panel auth-panel', 'aria-labelledby': 'auth-title' },
    el('div', { class: 'panel-shell' }, el('div', { class: 'panel-head' }, title, close), body)
  );

  close.addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', onDialogClose);
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) {
      dialog.close();
    }
  });
  body.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (target?.closest('[data-auth-logout]')) {
      void logout();
    } else if (target?.closest('[data-auth-refresh]')) {
      void loadOrders();
    }
  });
  document.body.append(dialog);
}

function readAuthErrorFromUrl(): string {
  const url = new URL(window.location.href);
  const code = url.searchParams.get('auth_error');
  if (code === null) {
    return '';
  }
  url.searchParams.delete('auth_error');
  const clean = `${url.pathname}${url.search}${url.hash}`;
  window.history.replaceState(null, '', clean);
  return errorMessages[code] ?? 'No pudimos iniciar sesión. Inténtalo de nuevo.';
}

/**
 * Inserta el botón "Ingresar" en el menú (antes del carrito) y prepara el panel de cuenta.
 * Si el servidor no tiene ningún proveedor configurado, el botón no se muestra.
 */
export function initAuth(beforeNode: HTMLElement): void {
  navButton = el('button', {
    type: 'button',
    class: 'nav-link auth-nav',
    'aria-haspopup': 'dialog',
    hidden: true
  });
  beforeNode.parentElement?.insertBefore(navButton, beforeNode);
  buildDialog();
  navButton.addEventListener('click', openDialog);

  const pendingError = readAuthErrorFromUrl();

  void (async () => {
    try {
      const [providersPayload, mePayload] = await Promise.all([
        getJson('/api/v1/auth/providers'),
        getJson('/api/v1/auth/me')
      ]);
      providers = parseProviders(providersPayload);
      user = parseUser(mePayload);
    } catch {
      providers = [];
      user = null;
    }
    loaded = true;
    syncNavButton();
    if (pendingError.length > 0 && !navButton.hidden) {
      errorText = pendingError;
      openDialog();
    }
  })();
}
