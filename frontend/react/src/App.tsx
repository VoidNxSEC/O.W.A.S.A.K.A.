import { ConsolePage } from './pages/ConsolePage';
import { HomePage } from './pages/HomePage';
import { IncidentsPage } from './pages/IncidentsPage';
import { TransparencyPage } from './pages/TransparencyPage';

const routes = {
  '/': HomePage,
  '/console': ConsolePage,
  '/transparency': TransparencyPage,
  '/incidents': IncidentsPage,
};

export default function App() {
  const Page = routes[window.location.pathname as keyof typeof routes] ?? HomePage;

  return <Page />;
}
