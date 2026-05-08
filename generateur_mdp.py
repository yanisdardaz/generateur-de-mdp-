#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Générateur de mots de passe (Python).

Fonctionnalités :
- Choix du nombre de caractères
- Choix de la complexité (faible / moyenne / forte / personnalisée)
- Génération via secrets (cryptographiquement robuste)

Exemples :
- python generateur_mdp.py --length 16 --complexity forte
- python generateur_mdp.py
"""

from __future__ import annotations

import argparse
import secrets
import sys
from typing import Iterable, Tuple


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Générer un mot de passe sécurisé.")
    parser.add_argument(
        "--length",
        type=int,
        default=16,
        help="Nombre de caractères du mot de passe (défaut: 16).",
    )
    parser.add_argument(
        "--complexity",
        type=str,
        default="forte",
        choices=["faible", "moyenne", "forte", "custom"],
        help="Complexité du mot de passe.",
    )
    parser.add_argument(
        "--custom-charset",
        type=str,
        default="",
        help="Utilisé uniquement si --complexity custom. Exemple: 'abcdXYZ123!@#'",
    )
    return parser.parse_args(list(argv))


def _charset_for_complexity(level: str, custom: str) -> Tuple[str, Tuple[str, ...]]:
    # On renvoie (charset_total, exigences) où exigences = types à inclure.
    # types possibles : 'lower', 'upper', 'digits', 'symbols'
    lower = "abcdefghijklmnopqrstuvwxyz"
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    digits = "0123456789"
    symbols = "!@#$%^&*()-_=+[]{};:,.?/|~"

    if level == "faible":
        return (lower + digits, ("lower", "digits"))
    if level == "moyenne":
        return (lower + upper + digits, ("lower", "upper", "digits"))
    if level == "forte":
        return (lower + upper + digits + symbols, ("lower", "upper", "digits", "symbols"))
    if level == "custom":
        charset = custom
        if not charset:
            raise ValueError("--custom-charset est requis quand --complexity custom.")
        # En custom, on ne force pas des catégories : on fait juste un choix uniforme.
        return (charset, ())

    raise ValueError(f"Complexité inconnue: {level}")


def generate_password(length: int, complexity: str, custom_charset: str = "") -> str:
    if length < 1:
        raise ValueError("La longueur doit être >= 1")

    charset, required_types = _charset_for_complexity(complexity, custom_charset)

    # Si on n’a pas d’exigences (custom), on choisit juste au hasard.
    if not required_types:
        return "".join(secrets.choice(charset) for _ in range(length))

    # Sinon on garantit au moins 1 caractère de chaque type.
    pools = {
        "lower": "abcdefghijklmnopqrstuvwxyz",
        "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits": "0123456789",
        "symbols": "!@#$%^&*()-_=+[]{};:,.?/|~",
    }

    if length < len(required_types):
        raise ValueError(
            f"Longueur trop petite pour la complexité '{complexity}'. "
            f"Il faut au moins {len(required_types)} caractères."
        )

    password_chars = [secrets.choice(pools[t]) for t in required_types]
    remaining = length - len(password_chars)
    password_chars.extend(secrets.choice(charset) for _ in range(remaining))

    # Mélange pour éviter que les catégories soient groupées.
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def main(argv: Iterable[str]) -> int:
    if not argv:
        # Mode interactif simple.
        print("=== Générateur de mot de passe ===")
        while True:
            try:
                length = int(input("Nombre de caractères (ex: 16): ").strip())
                break
            except ValueError:
                print("Valeur invalide. Entrez un nombre.")

        complexity = input("Complexité (faible/moyenne/forte): ").strip().lower() or "forte"
        if complexity not in {"faible", "moyenne", "forte", "custom"}:
            print("Complexité non reconnue. Utilisation de 'forte'.")
            complexity = "forte"

        custom_charset = ""
        if complexity == "custom":
            custom_charset = input("Entrez votre jeu de caractères (custom-charset): ").strip()

        pwd = generate_password(length=length, complexity=complexity, custom_charset=custom_charset)
        print("\nMot de passe généré :")
        print(pwd)
        return 0

    args = _parse_args(argv)
    try:
        pwd = generate_password(args.length, args.complexity, args.custom_charset)
    except ValueError as e:
        print(f"Erreur: {e}", file=sys.stderr)
        return 1

    print(pwd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

