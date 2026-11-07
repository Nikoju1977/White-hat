"""Opt-in, local-only firewall hardening. Never callable from the web API.

Designed to prevent an accidental remote lockout: refuses SSH sessions and
requires interactive terminal confirmation. Does not add or remove rules.
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys

from .collector import firewall_status, defender_status


def audit():
    print('AEGIS SHIELD — contrôle de prévention local')
    print(f'Système: {platform.system()} {platform.release()}')
    print(f'Pare-feu: {firewall_status()}')
    print(f'Defender: {defender_status()}')
    print('Remarque : cela ne garantit pas l’absence d’intrusion.')


def enable_firewall():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError('Activation refusée : terminal interactif local nécessaire')
    if any(os.environ.get(x) for x in ('SSH_CONNECTION','SSH_CLIENT','SSH_TTY')):
        raise RuntimeError('Activation refusée depuis une session SSH : risque de perdre l’accès')
    system=platform.system()
    if system == 'Windows':
        cmd=['powershell','-NoProfile','-NonInteractive','-Command',
             'Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop']
    elif system == 'Darwin':
        cmd=['/usr/libexec/ApplicationFirewall/socketfilterfw','--setglobalstate','on']
    elif system == 'Linux':
        if not shutil.which('ufw'):
            raise RuntimeError('UFW absent : configurez le pare-feu natif de votre distribution.')
        print('LINUX : vérifiez au préalable les règles SSH et services indispensables.')
        cmd=['ufw','--force','enable']
    else:
        raise RuntimeError('Plateforme non prise en charge')
    print('Cette opération active un pare-feu OS et peut couper des connexions existantes.')
    print('Exécutez depuis la console physique avec les privilèges administrateur.')
    ack=input('Tapez exactement ACTIVER pour continuer : ').strip()
    if ack!='ACTIVER':
        print('Aucune modification effectuée.')
        return
    result=subprocess.run(cmd,check=False,capture_output=True,text=True,timeout=30)
    print(result.stdout[:5000]);print(result.stderr[:2000],file=sys.stderr)
    if result.returncode:
        raise RuntimeError(f'Commande système échouée : code {result.returncode}')
    print('État après exécution :',firewall_status())
    print('Vérifiez immédiatement les accès nécessaires et votre stratégie réseau.')


def main():
    p=argparse.ArgumentParser(description='AEGIS SHIELD : prévention explicite uniquement')
    p.add_argument('command',choices=['audit','enable-firewall'])
    args=p.parse_args()
    if args.command=='audit':audit()
    else:
        try:enable_firewall()
        except (RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
            print('Erreur :',exc,file=sys.stderr)
            sys.exit(1)


if __name__=='__main__':main()
