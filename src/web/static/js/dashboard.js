document.addEventListener('DOMContentLoaded', function() {

    let protocolChart;

    const ctx = document.getElementById('protocolos-chart');
    if (ctx) {
        protocolChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    label: 'Distribución de Protocolos',
                    data: [],
                    backgroundColor: [
                        'rgba(255, 99, 132, 0.7)',
                        'rgba(54, 162, 235, 0.7)',
                        'rgba(255, 206, 86, 0.7)',
                        'rgba(75, 192, 192, 0.7)',
                        'rgba(153, 102, 255, 0.7)',
                        'rgba(255, 159, 64, 0.7)'
                    ],
                    borderColor: '#fff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    }
                }
            }
        });
    }

    function actualizarDashboard() {
        fetch('/api/datos_dashboard')
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    console.error('Error al cargar datos:', data.error);
                    return;
                }

                // Actualizar estadísticas generales
                const stats = data.estadisticas || {};
                document.getElementById('stat-paquetes').textContent = stats.paquetes_totales || '0';
                document.getElementById('stat-volumen').textContent = stats.bytes_totales_legible || '0 B';
                document.getElementById('stat-pps').textContent = stats.paquetes_por_segundo || '0';

                // Actualizar tabla de alertas
                const alertasTbody = document.getElementById('alertas-tbody');
                if (alertasTbody) {
                    alertasTbody.innerHTML = ''; // Limpiar tabla
                    const alertas = data.alertas || [];
                    if (alertas.length === 0) {
                         alertasTbody.innerHTML = '<tr><td colspan="5">No hay alertas recientes.</td></tr>';
                    } else {
                        alertas.forEach(alerta => {
                            const row = document.createElement('tr');
                            row.className = `severidad-${alerta.severidad.toLowerCase()}`;
                            row.innerHTML = `
                                <td>${alerta.timestamp}</td>
                                <td>${alerta.tipo}</td>
                                <td>${alerta.severidad}</td>
                                <td>${alerta.ip_origen || 'N/A'}</td>
                                <td>${alerta.mensaje}</td>
                            `;
                            alertasTbody.appendChild(row);
                        });
                    }
                }

                // Actualizar gráfico de protocolos
                if (protocolChart && stats.distribucion_protocolos) {
                    const protocolData = stats.distribucion_protocolos;
                    protocolChart.data.labels = Object.keys(protocolData);
                    protocolChart.data.datasets[0].data = Object.values(protocolData);
                    protocolChart.update();
                }

            })
            .catch(error => console.error('Error en la petición fetch:', error));
    }

    // Actualizar el dashboard cada 5 segundos
    actualizarDashboard();
    setInterval(actualizarDashboard, 5000);

});
