/**
 * Le fil des dernières actions avant l'erreur : navigations, requêtes en
 * échec, gestes. Anneau de N entrées, nettoyées à l'ajout.
 */
import { scrubText, scrubUrl } from './scrub.ts';
import { SENTINEL_LIMITS, type SentinelBreadcrumb } from './types.ts';

export class BreadcrumbTrail {
  private items: SentinelBreadcrumb[] = [];

  constructor(private readonly max: number = SENTINEL_LIMITS.breadcrumbs, private readonly clock: () => Date = () => new Date()) {}

  add(category: SentinelBreadcrumb['category'], message: string): void {
    const text = category === 'navigation'
      ? scrubUrl(message, SENTINEL_LIMITS.breadcrumbMessage) ?? ''
      : scrubText(message, SENTINEL_LIMITS.breadcrumbMessage);
    this.items.push({ at: this.clock().toISOString(), category, message: text });
    if (this.items.length > this.max) this.items.splice(0, this.items.length - this.max);
  }

  list(): SentinelBreadcrumb[] {
    return this.items.slice();
  }
}
