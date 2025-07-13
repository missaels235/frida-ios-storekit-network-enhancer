# frida-ios-storekit-network-enhancer

> Script de hooking avanzado para StoreKit y red en iOS con Frida v6.1.4  
> Creado por missaels235

---

## 🚀 Descripción

Este proyecto contiene un script para Frida que:

- **Monitoriza y modifica** el flujo de compras In-App (StoreKit).
- **Registra** en detalle las peticiones y respuestas de red (JSON, cabeceras, cuerpos).
- **Simula** respuestas de validación de compra exitosas para pruebas locales.
- Mejora la estabilidad y corrige errores de versiones anteriores (v6.1.4).

Perfecto para desarrolladores iOS y pentesters que quieran auditar o testear comportamientos de IAP y tráfico de red.

---

## 📦 Contenido

- `hook_storekit_network.js`  
  El script principal en JavaScript para ejecutar con Frida.
- `README.md`  
  Esta documentación.
- `LICENSE`  
  Licencia de uso (MIT por defecto).

---

## 🔧 Requisitos

- **Frida** ≥ 15.0.0  
- dispositivo/emulador iOS con jailbreak o Frida gadget instalado  
- **Node.js** (opcional, para herramientas auxiliares)

---

## 🛠️ Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/<tu-usuario>/frida-ios-storekit-network-enhancer.git
   cd frida-ios-storekit-network-enhancer
