import { createContext, useContext, useState, useEffect } from 'react'
import vi from './locales/vi'
import en from './locales/en'

const LanguageContext = createContext()

const DICTS = { vi, en }
const FALLBACK = en

export function LanguageProvider({ children }) {
  const [lang, setLang] = useState(() => {
    const saved = localStorage.getItem('language')
    return saved === 'en' ? 'en' : 'vi'
  })

  useEffect(() => {
    localStorage.setItem('language', lang)
    document.documentElement.lang = lang
  }, [lang])

  const t = (key, vars) => {
    const dict = DICTS[lang] || FALLBACK
    let s = dict[key]
    if (s == null) {
      s = FALLBACK[key]
      if (s == null) return key
    }
    if (vars) {
      for (const [k, v] of Object.entries(vars)) {
        s = s.replaceAll(`{${k}}`, v)
      }
    }
    return s
  }

  return (
    <LanguageContext.Provider value={{ lang, setLang, t }}>
      {children}
    </LanguageContext.Provider>
  )
}

export function useLanguage() {
  return useContext(LanguageContext)
}
