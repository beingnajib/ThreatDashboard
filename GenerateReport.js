import React, { Component } from 'react';
import axios from 'axios';

class GenerateReport extends Component {
    handleGenerateReport = () => {
        axios.get('/report/')
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
                <button onClick={this.handleGenerateReport}>Generate Report</button>
            </div>
        );
    }
}

export default GenerateReport;
