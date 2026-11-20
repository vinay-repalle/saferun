import { StrictMode } from 'react'
import { createRoot, hydrateRoot } from 'react-dom/client'
import './index.css' // global tokens first, so component stylesheets (imported by App) override them in the right order
import { App } from './App'
import { pageFor, upgradeLegacyHash } from './router'

// A built page arrives pre-rendered (data-page says which page): React takes over that HTML. If the address shows another page
// (an old #/guide link, or a dev server without pre-rendering), it renders from scratch instead.
upgradeLegacyHash()
const root = document.getElementById('root')
const app = <StrictMode><App /></StrictMode>
if (root.dataset.page && root.dataset.page === pageFor(window.location.pathname)) hydrateRoot(root, app)
else { root.replaceChildren(); createRoot(root).render(app) }
