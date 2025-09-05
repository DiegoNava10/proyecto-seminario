import React, { useState } from 'react';

function App() {
  const [ip, setIp] = useState('127.0.0.1');
  const [selectedIndex, setSelectedIndex] = useState(null);
  const [response, setResponse] = useState(null);
  const [loading, setLoading] = useState(false);

  // Vectores de prueba con 40 características (columna 'num_outbound_cmds' eliminada)
  const vectores = [
    {
      nombre: "Vector 1 - Normal",
      vector: ["0","tcp","ftp_data","SF","491","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","2","2","0.00","0.00","0.00","0.00","1.00","0.00","0.00","150","25","0.17","0.03","0.17","0.00","0.00","0.00","0.05","0.00"]
    },
    {
      nombre: "Vector 2 - (Neptune)",
      vector: ["0","tcp","private","S0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","123","6","1.00","1.00","0.00","0.00","0.05","0.07","0.00","255","26","0.10","0.05","0.00","0.00","1.00","1.00","0.00","0.00"]
    },
    {
      nombre: "Vector 3 - (Ipsweep)",
      vector: ["0","icmp","eco_i","SF","18","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","1","1","0.00","0.00","0.00","0.00","1.00","0.00","0.00","1","16","1.00","0.00","1.00","1.00","0.00","0.00","0.00","0.00"]
    }
  ];

  const handleSend = async () => {
    if (!ip || selectedIndex === null) {
      alert("Debes ingresar la IP del servidor y seleccionar un vector.");
      return;
    }
    setLoading(true);
    setResponse(null);

    const payload = {
      ip: ip,
      data: vectores[selectedIndex].vector
    };

    console.log("Payload que se envía:", JSON.stringify(payload));

    try {
      const res = await fetch(`http://${ip}:5000/analizar`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // ### CORRECCIÓN CLAVE ###
        // Enviamos el objeto 'payload' directamente, que ya tiene el formato correcto.
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      setResponse(data);
    } catch (err) {
      setResponse({ error: 'Error al conectar con el servidor: ' + err.message });
    } finally{
      setLoading(false);
    }
  };
  
  const styles = {
    app: { textAlign: 'center', padding: '2rem', fontFamily: 'Arial, sans-serif', color: '#333' },
    input: { width: '300px', marginBottom: '10px', padding: '8px', border: '1px solid #ccc', borderRadius: '4px' },
    select: { padding: '8px', border: '1px solid #ccc', borderRadius: '4px' },
    button: { padding: '10px 20px', cursor: 'pointer', backgroundColor: '#007bff', color: 'white', border: 'none', borderRadius: '4px', fontSize: '16px' },
    container: { textAlign: 'left', marginTop: '20px', margin: '20px auto', width: '90%', maxWidth: '800px' },
    pre: { backgroundColor: '#f4f4f4', padding: '15px', borderRadius: '5px', whiteSpace: 'pre-wrap', wordWrap: 'break-word', textAlign: 'left' }
  };

  const renderResponse = () => {
    if (!response) return null;
    const isErrorOrAttack = response.error || response.resultado === 'ataque';
    const responseStyle = { ...styles.pre, backgroundColor: isErrorOrAttack ? '#ffdddd' : '#ddffdd', border: `1px solid ${isErrorOrAttack ? 'red' : 'green'}`};
    return ( <div style={styles.container}> <h3>Respuesta del Servidor:</h3> <pre style={responseStyle}>{JSON.stringify(response, null, 2)}</pre> </div> );
  };

  return (
    <div style={styles.app}>
      <h2>Herramienta de Ciberseguridad IA</h2>
      <h4>Cliente de Pruebas NSL-KDD</h4>
      <input type="text" placeholder="IP del servidor" value={ip} onChange={e => setIp(e.target.value)} style={styles.input} />
      <h4>Selecciona un vector de prueba:</h4>
      <select onChange={e => setSelectedIndex(e.target.value)} defaultValue="" style={styles.select}>
        <option value="" disabled>-- Selecciona un vector --</option>
        {vectores.map((v, index) => ( <option key={index} value={index}>{v.nombre}</option> ))}
      </select>
      <br /><br />
      <button onClick={handleSend} disabled={loading} style={styles.button}>{loading ? 'Analizando...' : 'Enviar al Servidor'}</button>
      {selectedIndex !== null && ( <div style={styles.container}> <h4>Vector Seleccionado:</h4> <pre style={styles.pre}>{JSON.stringify(vectores[selectedIndex].vector, null, 2)}</pre> </div> )}
      {renderResponse()}
    </div>
  );
}

export default App;

