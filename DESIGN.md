# Design System

## Direction

Calm competition console. Interface favors task focus, explicit system state, and familiar controls over decoration. Light neutral workspace supports long-form reading; dark header anchors timer and session state.

## Color

- Page: `#f2f4f7`
- Surface: `#ffffff`
- Strong neutral: `#182231`
- Primary text: `#17202c`
- Muted text: `#566273`
- Border: `#d4dae2`
- Action and selection: `#1457d9`
- Warning: `#8a5200` on `#fff3d6`
- Error: `#b42318` on `#ffebe9`
- Success: `#17643a` on `#e5f5eb`

Color communicates action or state. It is not decorative. Every semantic state also carries text, shape, or border cues.

## Typography

Use `Segoe UI`, Aptos, then system sans. Use Cascadia Code or Consolas for timers, counts, and code snippets. Product headings use tight but readable tracking; body copy stays near 65 characters where practical.

## Shape

- Panels: 14px radius
- Controls: 8px radius
- Compact tags: 4-6px radius
- Cards use either border or restrained short shadow, never both as decoration.

## Layout

- Global content width: 75rem
- Exam: flexible question column plus 19rem navigator
- At 900px: navigator moves above question content and becomes static
- At 640px: toolbars and actions stack; controls remain full-width and at least 44px high

## Components

- Primary button: blue fill, white text, reserved for one next or final action
- Secondary button: white surface, defined border
- Quiet button: dark-header utility action only
- Options: semantic radio inputs inside full-row labels
- Navigator: semantic buttons with answered, flagged, and current states
- Dialog: native `dialog` for focus management and Escape support
- Alerts and save status: live regions with direct recovery-oriented language

## Motion

Motion only confirms state transitions: a 180ms view entrance and 100-160ms control feedback. Reduced-motion preference collapses all animation and transition durations.

## Accessibility

Target WCAG 2.2 AA. Maintain visible focus, semantic landmarks and controls, keyboard operation, live status announcements, non-color state cues, reduced motion, minimum 44px control targets, and horizontal overflow handling for admin tables.
