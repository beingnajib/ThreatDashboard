import React, { Component } from 'react';
import axios from 'axios';

class ImportData extends Component {
    handleFileUpload = event => {
        const file = event.target.files[0];
        const formData = new FormData();
        formData.append('file', file);
        axios.post('/import/', formData)
            .then(response => {
                console.log(response.data);
            })
            .catch(error => {
                console.error(error);
            });
    };

    render() {
        return (
            <div>
                <input type="file" onChange={this.handleFileUpload} />
            </div>
        );
    }
}

export default ImportData;
