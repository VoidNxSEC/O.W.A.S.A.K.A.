// @ts-check

const config = {
  title: 'O.W.A.S.A.K.A. SIEM',
  tagline: 'Open Watchful Air-gapped Security Analysis Kit & Architecture',
  url: process.env.SITE_URL ?? 'https://voidnxsec.github.io',
  baseUrl: process.env.BASE_URL ?? '/O.W.A.S.A.K.A./',
  organizationName: 'VoidNxSEC',
  projectName: 'O.W.A.S.A.K.A.',
  deploymentBranch: 'gh-pages',
  trailingSlash: false,
  onBrokenLinks: 'warn',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      },
    ],
  ],

  themeConfig: {
    navbar: {
      title: 'O.W.A.S.A.K.A.',
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docs',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://github.com/VoidNxSEC/O.W.A.S.A.K.A.',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Architecture',
              to: '/architecture/OVERVIEW',
            },
            {
              label: 'Deployment',
              to: '/deployment',
            },
            {
              label: 'Runbooks',
              to: '/runbooks/INCIDENT',
            },
          ],
        },
        {
          title: 'Project',
          items: [
            {
              label: 'Repository',
              href: 'https://github.com/VoidNxSEC/O.W.A.S.A.K.A.',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} O.W.A.S.A.K.A. SIEM.`,
    },
    prism: {
      additionalLanguages: ['bash', 'go', 'json', 'yaml'],
    },
  },
};

module.exports = config;
