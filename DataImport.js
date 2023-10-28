import React from 'react';
import axios from 'axios';

class DataImport extends React.Component {
    handleFileUpload = event => {
        const file = event.target.files[0];
        const formData = new FormData();
        formData.append('file', file);

        axios.post('/import', formData)
            .then(response => console.log(response))
            .catch(error => console.error(error));
    };

    render() {
        return (
            <div>
                <input type="file" onChange={this.handleFileUpload} />
                <button onClick={this.handleFileUpload}>Import</button>
            </div>
        );
    }
}

export default DataImport;
