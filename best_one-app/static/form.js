// Function to handle form submission
document.getElementById('pump-sales-form').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent default form submission

    // Get form data
    const formData = new FormData(this);

    // Send form data to server
    fetch('/pump_sales', {
        method: 'POST',
        body: formData, // Send form data as FormData
    })
    .then(response => response.json())
    .then(data => {
        // Display pump sales
        const pumpSalesDisplay = document.getElementById('pump-sales-display');
        pumpSalesDisplay.innerHTML = ''; // Clear previous content

        // Loop through data and display pump sales
        for (const [pump, sales] of Object.entries(data)) {
            const pumpSalesItem = document.createElement('div');
            pumpSalesItem.textContent = `Pump ${pump}: ${sales_litres} litres`;
            pumpSalesDisplay.appendChild(pumpSalesItem);
        }
    })
    .catch(error => console.error('Error:', error));
});
