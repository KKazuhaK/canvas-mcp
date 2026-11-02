export interface SenderLike {
  id?: string;
  url?: string;
  tab?: { id?: number };
}

// The popup (or the same page opened in a tab) is an extension page: it carries
// our extension id and a chrome-extension:// / moz-extension:// URL for popup.html.
// Content scripts carry the host page's URL, so they cannot pass this check.
export function isPopupSender(sender: SenderLike, extensionId: string, popupUrl: string): boolean {
  return sender.id === extensionId && typeof sender.url === 'string' && sender.url.split(/[?#]/)[0] === popupUrl;
}
