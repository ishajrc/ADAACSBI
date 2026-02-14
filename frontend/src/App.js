import { useState } from "react";

function App() {
  const [amount, setAmount] = useState("");
  const [result, setResult] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();

    const response = await fetch("/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ amount })
    });

    const data = await response.json();

    if (data.risk_level) {
      setResult(`Risk Level: ${data.risk_level}`);
    } else {
      setResult(data.error);
    }
  };

  return (
    <div style={{ textAlign: "center", marginTop: "50px" }}>
      <h1>ADACCSBI Transaction Analyzer</h1>

      <form onSubmit={handleSubmit}>
        <input
          type="number"
          placeholder="Enter transaction amount"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
        <br /><br />
        <button type="submit">Analyze</button>
      </form>

      <h2>{result}</h2>
    </div>
  );
}

export default App;