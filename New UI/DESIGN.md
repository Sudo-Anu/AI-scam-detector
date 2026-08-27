---
name: Guardian AI
colors:
  surface: '#11131c'
  surface-dim: '#11131c'
  surface-bright: '#373943'
  surface-container-lowest: '#0c0e17'
  surface-container-low: '#191b24'
  surface-container: '#1d1f29'
  surface-container-high: '#282933'
  surface-container-highest: '#32343e'
  on-surface: '#e1e1ef'
  on-surface-variant: '#dcbed4'
  inverse-surface: '#e1e1ef'
  inverse-on-surface: '#2e303a'
  outline: '#a4899d'
  outline-variant: '#50434c'
  surface-tint: '#ffabf3'
  primary: '#ffd7f5'
  on-primary: '#551353'
  primary-container: '#ffabf3'
  on-primary-container: '#7d3878'
  inverse-primary: '#8a4484'
  secondary: '#d3fbff'
  on-secondary: '#00363a'
  secondary-container: '#00eefc'
  on-secondary-container: '#00686f'
  tertiary: '#eaddff'
  on-tertiary: '#3c0090'
  tertiary-container: '#d1bcff'
  on-tertiary-container: '#6500e7'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#ffd7f5'
  primary-fixed-dim: '#ffabf3'
  on-primary-fixed: '#380038'
  on-primary-fixed-variant: '#6f2c6b'
  secondary-fixed: '#7df4ff'
  secondary-fixed-dim: '#00dbe9'
  on-secondary-fixed: '#002022'
  on-secondary-fixed-variant: '#004f54'
  tertiary-fixed: '#e9ddff'
  tertiary-fixed-dim: '#d1bcff'
  on-tertiary-fixed: '#23005b'
  on-tertiary-fixed-variant: '#5700c9'
  background: '#11131c'
  on-background: '#e1e1ef'
  surface-variant: '#32343e'
  surface-glass: rgba(255, 255, 255, 0.1)
  border-glass: rgba(255, 255, 255, 0.2)
typography:
  headline-xl:
    fontFamily: Geist
    fontSize: 48px
    fontWeight: '700'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-lg-mobile:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  body-md:
    fontFamily: Geist
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-sm:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-caps:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0.08em
  mono-data:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  margin-mobile: 16px
  margin-desktop: 40px
  gutter: 24px
  glass-padding: 32px
  sidebar-width: 280px
---

## Brand & Style

Guardian AI is a cybersecurity-focused interface that blends **Glassmorphism** with a **Futuristic/High-Tech** aesthetic. The brand personality is vigilant, sophisticated, and technologically advanced, designed to evoke a sense of "active protection" and digital "forensics."

The visual style utilizes deep nocturnal tones as a base, overlaid with translucent glass panels, vibrant neon accents (magenta and cyan), and "laser" scan effects. The UI prioritizes a sense of depth and luminosity, mimicking a high-end security dashboard or a sci-fi command center. 

**Key Characteristics:**
- **Translucency:** Heavy use of backdrop blurs (20px-40px) to simulate layered glass.
- **Luminosity:** Elements "glow" through subtle radial gradients and primary-colored shadows.
- **Dynamic Energy:** Animated pulse effects and scanning line animations reinforce the AI's active presence.

## Colors
The palette is rooted in a **Dark** color mode, using a deep navy-charcoal (`#11131c`) for the background to make vibrant accent colors pop.

- **Primary (Electric Pink):** Used for critical actions, active states, and "high-risk" highlights.
- **Secondary (Cyan/Teal):** Used for "safe" status indicators and supporting technological accents.
- **Tertiary (Deep Purple):** Used for gradients and background depth blurs.
- **Neutral (Slate Blue/Grey):** Used for text and secondary interface elements, keeping them legible against the dark backdrop.

The system relies heavily on **Opacity Levels** for glass effects (10-15% white with 20px blur) rather than solid color fills for surfaces.

## Typography
The system uses **Geist** as the primary typeface for its clean, technical, and modern feel, suitable for a technology-driven brand. 

**JetBrains Mono** is utilized for labels, technical data, and input fields to reinforce the "code" and "analysis" aspect of the tool. 

Key headers use tight letter spacing and heavy weights to create a sense of urgency and authority, while monospaced labels are all-caps with generous letter spacing to provide a systematic, data-driven appearance.

## Layout & Spacing
The layout follows a **Fixed Sidebar + Fluid Content** model on desktop. 

- **Sidebar:** A fixed 280px navigation rail on the left, using a translucent background.
- **Main Content:** Centered, max-width container (4xl/768px - 3xl/896px) for the core analysis cards.
- **Rhythm:** A 4px/8px baseline grid is used. Sections are separated by large gutters (40px on desktop) to allow the background gradients and glass effects enough "breathing room."
- **Mobile Adaptivity:** The sidebar is hidden on mobile, replaced by a bottom-sheet or hidden drawer (not shown), while margins shrink from 40px to 16px to maximize utility on smaller screens.

## Elevation & Depth
Depth is achieved through **Glassmorphism and Tonal Gradients** rather than traditional drop shadows.

1.  **Level 0 (Background):** Solid `#11131c` with large, low-opacity radial gradients (primary and tertiary) to create atmospheric depth.
2.  **Level 1 (Navigation/Panels):** 10% white opacity with a 20px blur and a subtle 20% white border.
3.  **Level 2 (Active Analysis Hub):** 15% white opacity with a 40px blur. This level includes a multi-layered border: a base 1px transparent border with a linear-gradient secondary border to simulate a "glowing" edge.
4.  **Level 3 (Buttons/Popups):** High-saturation gradients (Primary to Tertiary) with a soft outer glow shadow matching the primary color (e.g., `0 0 12px theme('colors.primary')`).

## Shapes
The shape language is modern and "Soft-Rounded."

- **Cards/Hubs:** Large 2xl (1.5rem) rounded corners for main containers.
- **Interactive Elements:** Buttons and Input fields use xl (0.75rem) or lg (0.5rem) roundedness.
- **Status/Tags:** Pill-shaped (9999px) for chips and toggle filters to distinguish them from structural elements.
- **Icons:** Encapsulated in rounded-xl containers with subtle background tints.

## Components

### Buttons
- **Primary:** Full gradient (Primary to Tertiary), bold text, white foreground. Includes a hover state with a color-matched outer glow.
- **Ghost/Glass:** Transparent with a thin white/20% border. Used for secondary navigation actions.
- **Filter Chips:** Pill-shaped; active state uses a low-opacity primary background and a high-contrast border.

### Input Fields
- **Glass Inputs:** Semi-transparent dark background, bottom-aligned focus border (Primary color). Uses `JetBrains Mono` for entered text to emphasize the data-entry nature.

### Cards
- **Analysis Hub:** Uses the "Active" glass style. Includes an internal "laser" line animation (`absolute` position) that triggers during active states to visualize the scanning process.

### Navigation
- **Sidebar Links:** High-contrast active state with a solid left-border (2px Primary). Hover states use a subtle 5% white background increase.

### Indicators
- **Scanning Pulse:** Small secondary-colored dots with a CSS `animate-ping` to indicate live connection or activity.