<#
.SYNOPSIS
    Script de gestion pour le projet EASM (Remplacement du Makefile pour Windows)

.DESCRIPTION
    Permet de lancer les commandes courantes de build, start, stop, logs, etc.

.EXAMPLE
    .\manage.ps1 build
    .\manage.ps1 up
    .\manage.ps1 logs
#>

param (
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateSet("build", "up", "down", "logs", "shell-backend", "shell-worker", "clean", "help")]
    [string]$Command
)

switch ($Command) {
    "build" {
        Write-Host "Building services..." -ForegroundColor Cyan
        docker-compose build
    }
    "up" {
        Write-Host "Starting services..." -ForegroundColor Cyan
        docker-compose up -d
    }
    "down" {
        Write-Host "Stopping services..." -ForegroundColor Cyan
        docker-compose down
    }
    "logs" {
        Write-Host "Showing logs..." -ForegroundColor Cyan
        docker-compose logs -f
    }
    "shell-backend" {
        Write-Host "Entering backend shell..." -ForegroundColor Cyan
        docker-compose exec backend /bin/bash
    }
    "shell-worker" {
        Write-Host "Entering worker shell..." -ForegroundColor Cyan
        docker-compose exec worker_discovery /bin/bash
    }
    "clean" {
        Write-Host "Cleaning up..." -ForegroundColor Cyan
        docker-compose down -v --remove-orphans
        docker system prune -f
    }
    "help" {
        Get-Help $MyInvocation.MyCommand.Path -Detailed
    }
}
