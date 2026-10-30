import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css' // global tokens first, so component stylesheets (imported by App) override them in the right order
import { App } from './App'

createRoot(document.getElementById('root')).render(<StrictMode><App /></StrictMode>)
