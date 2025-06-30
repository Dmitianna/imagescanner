#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import click
from src.core import describe_image, check_official, check_vulns

@click.command(help="""
imagescanner — утилита для анализа безопасности Docker-образов.

Возможности:
  --check-official   Проверка официальности образа через Docker Hub API.
  --check-vulns      Проверка системных пакетов (dpkg) на уязвимости через базу OSV.

Пример использования:
  imagescanner --image python:3.9-slim --check-vulns --check-official
""")
@click.option('--image', required=True, help='Имя Docker-образа (например, nginx:latest)')
@click.option('--check-official', 'do_check_official', is_flag=True, help='Проверить официальность образа через Docker Hub')
@click.option('--check-vulns', 'do_check_vulns', is_flag=True, help='Проверить системные пакеты на уязвимости (dpkg + OSV)')
def main(image, do_check_official, do_check_vulns):
    click.secho(f"[INFO] Анализ Docker-образа: {image}", fg="cyan")

    describe_image(image)

    if do_check_official:
        click.echo("→ Проверка официальности образа...")
        check_official(image)

    if do_check_vulns:
        click.echo("→ Проверка системных уязвимостей...")
        check_vulns(image)

if __name__ == '__main__':
    main()

