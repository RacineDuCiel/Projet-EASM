import asyncio
import sys
import os
from getpass import getpass

# Add backend directory to python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.db.session import AsyncSessionLocal
from src.models.user import User
from src.models.enums import UserRole
from src.core.security import get_password_hash
from sqlalchemy import select

async def create_admin():
    print("=== Création d'un utilisateur Administrateur ===")
    username = input("Nom d'utilisateur (ex: admin): ")
    if not username:
        print("Erreur: Le nom d'utilisateur est requis.")
        return

    password = getpass("Mot de passe: ")
    if not password:
        print("Erreur: Le mot de passe est requis.")
        return
        
    confirm_password = getpass("Confirmer le mot de passe: ")
    if password != confirm_password:
        print("Erreur: Les mots de passe ne correspondent pas.")
        return

    async with AsyncSessionLocal() as session:
        # Check if user exists
        result = await session.execute(select(User).where(User.username == username))
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            print(f"Erreur: L'utilisateur '{username}' existe déjà.")
            return

        hashed_password = get_password_hash(password)
        new_user = User(
            username=username,
            hashed_password=hashed_password,
            role=UserRole.admin,
            is_active=True
        )
        
        session.add(new_user)
        await session.commit()
        print(f"\nSuccès ! L'utilisateur admin '{username}' a été créé.")

if __name__ == "__main__":
    try:
        asyncio.run(create_admin())
    except KeyboardInterrupt:
        print("\nOpération annulée.")
    except Exception as e:
        print(f"\nUne erreur est survenue: {e}")
