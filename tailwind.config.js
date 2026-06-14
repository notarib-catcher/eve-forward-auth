module.exports = {
  content: [
    "./templates/**/*.html",
    "./templates/*.html"
  ],
  theme: {
    extend: {

      colors: {
        eve: {
          bg:         '#00000f',
          border:     '#1a4a60',
          surface:    'rgba(0, 8, 20, 0.92)',

          // Text ramp
          dim:        '#1e4a5e',
          mid:        '#2a5a70',
          base:       '#3a7fa0',
          bright:     '#7ab3d4',
          high:       '#a8d8f0',
          white:      '#e0f4ff',

          // Accents
          teal:       '#4af0c8',
          amber:      '#f0c84a',
          red:        '#f04a4a',
          purple:     '#a04af0',
        },
      },

      fontFamily: {
        eve: ['Courier New', 'Courier', 'monospace'],
      },

      fontSize: {
        'eve-xs':   ['10px', { lineHeight: '2' }],
        'eve-sm':   ['11px', { lineHeight: '2' }],
        'eve-md':   ['13px', { lineHeight: '1.8' }],
        'eve-lg':   ['18px', { lineHeight: '1.4' }],
      },

      letterSpacing: {
        'eve-sm':   '0.1em',
        'eve-md':   '0.2em',
        'eve-lg':   '0.35em',
      },

    },
  },
};