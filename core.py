#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import docker
import click
import requests
import subprocess
import json
#-----------------------------------------------------------------------------------------------
# Проверяет, доступен ли образ локально. Не загружает его автоматически.
def ensure_image_available(image_name: str) -> bool:
    try:
        client = docker.from_env()
        try:
            client.images.get(image_name)
            return True
        except docker.errors.ImageNotFound:
            click.secho(f"[!] Образ '{image_name}' не найден локально.", fg="yellow")
            return False
        except docker.errors.APIError as e:
            click.secho(f"[Ошибка] Не удалось получить образ: {e}", fg="red")
            return False
    except Exception as e:
        click.secho(f"[Ошибка] Не удалось инициализировать Docker-клиент: {e}", fg="red")
        return False
#-----------------------------------------------------------------------------------------------
def describe_image(image_name: str):
    client = docker.from_env()

    try:
        image = client.images.get(image_name)
    except docker.errors.ImageNotFound:
        click.secho(f"[!] Образ '{image_name}' не найден.", fg="red")
        return

    image_id = image.id 
    tags = image.tags
    created = image.attrs.get("Created", "")
    size = image.attrs.get("Size", 0) / 1024 / 1024
    digests = image.attrs.get("RepoDigests", [])

    click.secho(f"\n[INFO] Образ ID: {image_id}", fg="cyan")
    click.secho(f"[INFO] Теги: {', '.join(tags) if tags else '—'}", fg="cyan")
    click.secho(f"[INFO] RepoDigests: {', '.join(digests) if digests else '—'}", fg="cyan")
    click.secho(f"[INFO] Дата сборки: {created}", fg="cyan")
    click.secho(f"[INFO] Размер: {size:.2f} MB", fg="cyan")
#-----------------------------------------------------------------------------------------------
# Проверяет, существует ли тег образа в официальном репозитории Docker Hub.
def check_official(image_name: str):
    try:
        if ":" in image_name:
            repo, tag = image_name.split(":", 1)
        else:
            repo, tag = image_name, "latest"

        repo_short = repo.split("/")[-1]
        url = f"https://hub.docker.com/v2/repositories/library/{repo_short}/tags/{tag}/"
        response = requests.get(url)

        if response.status_code == 200:
            click.secho(f"[OK] Образ '{repo}:{tag}' найден в официальном репозитории Docker Hub.", fg="green")
        elif response.status_code == 404:
            click.secho(f"[!] Образ '{repo}:{tag}' не найден среди официальных.", fg="yellow")
        else:
            click.secho(f"[!] Не удалось выполнить запрос к Docker Hub (код {response.status_code}).", fg="red")

    except Exception as e:
        click.secho(f"[Ошибка] {e}", fg="red")
#-----------------------------------------------------------------------------------------------------------------
# Проверяет системные зависимости образа через OSV.
def check_vulns(image_name: str):
    try:
        client = docker.from_env()
        client.images.get(image_name)
    except docker.errors.ImageNotFound:
        click.secho(f"[!] Образ '{image_name}' не найден.", fg="red")
        return

    click.secho(f"[INFO] Извлечение списка пакетов из {image_name}...", fg="cyan")
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", image_name, "dpkg-query", "-W", "-f=${Package} ${Version}\\n"],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            click.secho("dpkg-query не сработал — возможно, образ не основан на Debian.", fg="yellow")
            return

        packages = []
        for line in result.stdout.strip().splitlines():
            try:
                name, version = line.strip().split(" ", 1)
                packages.append((name, version))
            except ValueError:
                continue

        if not packages:
            click.secho("Пакеты не найдены.", fg="yellow")
            return

        click.secho(f"[INFO] Найдено {len(packages)} пакетов. Проверка через OSV...", fg="cyan")

        vuln_count = 0

        for name, version in packages:
            osv_query = {
                "package": {"name": name, "ecosystem": "Debian"},
                "version": version
            }
            try:
                response = requests.post("https://api.osv.dev/v1/query", json=osv_query, timeout=10)
                if response.status_code == 200 and response.json().get("vulns"):
                    vuln_count += len(response.json()["vulns"])
                    for vuln in response.json()["vulns"]:
                        click.secho(f"[OSV] {name} {version} → {vuln['id']}: {vuln.get('summary', 'Нет описания')}", fg="red")
            except Exception as e:
                click.secho(f"[OSV] Ошибка при проверке {name}: {e}", fg="yellow")

        click.secho(f"\n[Итог] Уязвимостей найдено через OSV: {vuln_count}", fg="blue")

    except Exception as e:
        click.secho(f"[ERROR] Ошибка при анализе образа: {e}", fg="red")


