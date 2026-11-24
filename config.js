/* Endereço da API. '/prod' = mesmo domínio do site (CloudFront encaminha /prod/* para a API; também vale no `npm run local`).
   Só troque por um endereço completo (https://....execute-api...amazonaws.com/prod) se o site estiver em OUTRO domínio
   que não o criado pelo template; nesse caso informe esse domínio em AllowedOrigin no deploy. */
window.BOPE_CONFIG = { apiUrl: '/prod' };
