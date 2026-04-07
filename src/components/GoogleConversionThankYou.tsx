import { useEffect } from 'react';

export function GoogleConversionThankYou() {
  useEffect(() => {
    // Verifica se é a página de obrigado
    const isThankYouPage = window.location.pathname.includes('obrigado') || 
                           window.location.pathname.includes('thank-you') ||
                           window.location.pathname.includes('confirmacao');
    
    if (isThankYouPage && typeof gtag !== 'undefined') {
      gtag('event', 'conversion', {
        'send_to': 'AW-18071632226/IEXQCPrM4ZccEOLynKlD'
      });
      console.log('✅ Conversão registrada - Página Obrigado');
    }
  }, []);

  return null;
}
