import * as L from "lucide-react";
import type { LucideIcon } from "lucide-react";

/**
 * Icon registry built on lucide-react (feather-style, stroke based).
 * Keeps a single `Icon` component + `IconName` union for the whole app
 * while reusing the full Lucide icon library for the sidebar.
 */

const ICONS: Record<string, LucideIcon> = {
  // core UI
  shield: L.Shield,
  shieldCheck: L.ShieldCheck,
  shieldAlert: L.ShieldAlert,
  shieldOff: L.ShieldOff,
  alert: L.TriangleAlert,
  warn: L.CircleAlert,
  activity: L.Activity,
  file: L.File,
  fileSearch: L.FileSearch,
  fileStack: L.FileStack,
  fileText: L.FileText,
  server: L.Server,
  crosshair: L.Crosshair,
  search: L.Search,
  cpu: L.Cpu,
  target: L.Target,
  lock: L.Lock,
  lockKeyhole: L.LockKeyhole,
  database: L.Database,
  databaseBackup: L.DatabaseBackup,
  chart: L.BarChart3,
  flag: L.Flag,
  globe: L.Globe,
  sliders: L.SlidersHorizontal,
  check: L.Check,
  x: L.X,
  layers: L.Layers,
  download: L.Download,
  octagon: L.OctagonAlert,
  copy: L.Copy,
  list: L.List,
  drive: L.HardDrive,
  trend: L.TrendingUp,
  zap: L.Zap,
  clock: L.Clock,
  bookmark: L.Bookmark,
  external: L.ExternalLink,
  eye: L.Eye,
  box: L.Package,
  book: L.Book,
  bookOpen: L.BookOpen,
  bookOpenCheck: L.BookOpenCheck,
  award: L.Award,
  radio: L.RadioTower,
  clipboard: L.ClipboardList,
  clipboardCheck: L.ClipboardCheck,
  users: L.Users,
  play: L.Play,
  plus: L.Plus,
  refresh: L.RefreshCw,
  scan: L.Scan,
  git: L.GitBranch,
  gauge: L.Gauge,
  chevron: L.ChevronRight,
  arrowLeft: L.ArrowLeft,
  filter: L.Filter,

  // sidebar: home & explore
  home: L.Home,
  compass: L.Compass,
  dashboard: L.LayoutDashboard,
  reports: L.FileText,
  alerting: L.Bell,
  notifications: L.BellRing,
  maps: L.Map,

  // sidebar: endpoint / assets / agents
  monitor: L.Monitor,
  monitorCog: L.MonitorCog,
  bug: L.Bug,
  network: L.Network,
  scrollText: L.ScrollText,
  terminal: L.Terminal,
  usb: L.Usb,
  userRound: L.UserRound,
  userCog: L.UserCog,
  userPlus: L.UserPlus,
  fingerprint: L.Fingerprint,
  router: L.Router,
  smartphone: L.Smartphone,
  archive: L.Archive,
  gavel: L.Gavel,
  braces: L.Braces,
  flaskConical: L.FlaskConical,
  wrench: L.Wrench,
  settings: L.Settings,
  beaker: L.Beaker,

  // sidebar: threat intel / ai
  rss: L.Rss,
  history: L.History,
  sparkles: L.Sparkles,
  brain: L.Brain,
  brainCircuit: L.BrainCircuit,
  bot: L.Bot,
  folderOpen: L.FolderOpen,
  messageSquare: L.MessageSquare,
  lightbulb: L.Lightbulb,
  wand2: L.Wand2,
  briefcase: L.Briefcase,

  // sidebar: compliance / cloud / system
  badgeCheck: L.BadgeCheck,
  creditCard: L.CreditCard,
  heartPulse: L.HeartPulse,
  scale: L.Scale,
  cloud: L.Cloud,
  cloudy: L.Cloudy,
  container: L.Container,
  boxes: L.Boxes,
  gitBranch: L.GitBranch,
  mail: L.Mail,
  keyRound: L.KeyRound,
  plug: L.Plug,
  info: L.Info,
};

export type IconName = keyof typeof ICONS;

export function Icon({
  name,
  size = 16,
  className,
  strokeWidth = 2,
}: {
  name: IconName;
  size?: number;
  className?: string;
  strokeWidth?: number;
}) {
  const Cmp = ICONS[name];
  return <Cmp size={size} className={className} strokeWidth={strokeWidth} aria-hidden="true" />;
}
