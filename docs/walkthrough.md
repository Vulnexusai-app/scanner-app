# Walkthrough: Integração com Stripe — Pagamentos Recorrentes (Fase 3)

Esta fase implementou o sistema completo de faturamento para o `scanner-app`, permitindo que usuários façam upgrade para o plano Pro de forma automatizada.

## 1. Infraestrutura Stripe (Backend)
- **Serviço**: Criado `stripeService.js` para gerenciar a instância do Stripe.
- **Rotas de Billing**: Implementados endpoints em `billing.js`:
    - `POST /api/billing/create-checkout`: Cria sessão de checkout para o plano Pro.
    - `POST /api/billing/portal`: Abre o portal de gestão de assinatura oficial do Stripe.
    - `GET /api/billing/status`: Recupera o status do plano atual do usuário.
    - `POST /api/billing/webhook`: Processa eventos em tempo real (pagamento concluído, falha, cancelamento).
- **Proteção Webhook**: Configurado `express.raw` no `app.js` para permitir a validação da assinatura de eventos do Stripe (`constructEvent`).

## 2. Banco de Dados e Segurança
- **Migração SQL**: Adicionada a coluna `stripe_customer_id` à tabela `users` para vincular usuários locais a clientes do Stripe.
- **Sincronização**: O Webhook atualiza automaticamente a tabela `user_plans` no Supabase conforme o status da assinatura no Stripe.

## 3. Interface do Usuário (Frontend)
- **Checkout**: Botões "Assinar Pro" em `pricing.html` e `dashboard.html` iniciam o fluxo de pagamento com feedback visual de "Processando".
- **Gestão**: Usuários Pro agora veem um botão "Gerenciar Assinatura" no dashboard que leva ao portal do Stripe.
- **Feedback Visual**: Implementada detecção de retorno via URL (`?upgrade=success`) para exibir notificações toast de sucesso ou cancelamento.

## 4. Verificação Realizada
- [x] SDK Stripe carregado corretamente.
- [x] Endpoints respondendo adequadamente (401 sem token).
- [x] Middleware de Raw Body operante para webhooks.

---
*Fase 3 concluída. O sistema de monetização está pronto para produção.*
