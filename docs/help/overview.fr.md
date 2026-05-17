---
title: Présentation d'Andy Auth
slug: andy-auth-overview
order: 1
tags: [auth, identity, oidc]
---

# Présentation d'Andy Auth

Andy Auth est le fournisseur d'identité OAuth2/OIDC de l'écosystème Andy. Il prend en charge l'identité utilisateur, les sessions, l'authentification multi-facteurs et l'enregistrement des clients OAuth, et constitue le serveur d'autorisation basé sur OpenIddict auquel chaque autre service Andy fait confiance.

## Ce qu'il fait

- Émet des jetons d'accès et de rafraîchissement pour les sessions humaines et les clients machine-à-machine (M2M).
- Héberge le document de découverte à `/auth/.well-known/openid-configuration` pour que les autres services localisent l'émetteur, le JWKS et les scopes pris en charge sans configuration statique.
- Gère les enregistrements de clients OAuth — chaque service qui émet ou accepte des jetons possède une entrée client ici.
- Applique les défis MFA (TOTP aujourd'hui ; passkey/WebAuthn dans la feuille de route).
- Publie les événements de session sur NATS pour que les services dépendants réagissent à la déconnexion et à la révocation.

## Concepts clés

- **Audience** — chaque API a une audience URN (`urn:andy-rbac-api`, `urn:andy-tasks-api`, …). Les jetons sont émis pour une audience spécifique et rejetés par toute autre.
- **Scopes** — permissions fines à l'intérieur d'une audience, comme `tasks:write` ou `rbac:roles:assign`.
- **Client M2M** — identifiants service-à-service, distincts des sessions utilisateur. Conductor lit les secrets des clients M2M via `andy-settings`.

## Où il s'intègre

Tous les autres services dépendent d'Andy Auth pour valider les jetons bearer. Andy Auth lui-même ne dépend que de sa propre base de données PostgreSQL. Si Auth tombe, chaque endpoint protégé du parc se met à renvoyer 401.

## Configuration

Les clés de fournisseur, les URL de rappel autorisées et la politique MFA résident dans `config/registration.json`. Conductor expose le catalogue en lecture seule sous **Réglages → Catalogues → Services → Andy Auth**.

## Dépannage

- **Erreurs IDX10*** dans les logs de service — la validation JWT a échoué. Le plus souvent l'audience ou l'émetteur ne correspond pas ; vérifiez le réglage `Authentication:Authority` du service consommateur par rapport au document de découverte d'Auth.
- **`[API-AUTH-401]` répété dans les logs Conductor** — le jeton d'accès en cache a expiré et le rafraîchissement a échoué. Une nouvelle connexion débloque généralement ; les échecs persistants pointent vers un décalage d'horloge entre Conductor et Auth.
- **Erreurs `IDS2*`** — OpenIddict a rejeté la forme de la requête. Le code d'erreur indique exactement quel paramètre est manquant ou mal formé.
