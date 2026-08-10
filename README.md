# Julisita Vtas — Tienda real

## Qué incluye
- Catálogo con 12 productos y precios de Julisita Vtas.
- Carrito con múltiples productos y cantidades.
- Creación real de pedidos en el servidor.
- Guardado persistente en `data/orders.json`.
- Número de pedido `JV-...`.
- Consulta pública de pedido por número.
- Login de administradora.
- Buscador de pedidos por número, nombre, ID, región o estado.
- Cambio de estado: PENDIENTE, EN PROCESO, COMPLETADO, CANCELADO.
- Estadísticas del administrador.

## Clave inicial
`JULISITA2026`

## Ejecutar
1. Instalar Node.js 18 o superior.
2. Abrir una terminal en esta carpeta.
3. Ejecutar:
   `npm install`
4. Ejecutar:
   `npm start`
5. Abrir:
   `http://localhost:3000`

## Publicación
Después de comprobarla localmente, esta misma carpeta se puede desplegar en un hosting Node.js. No abrir `index.html` con doble clic: el sistema necesita `server.js`.
