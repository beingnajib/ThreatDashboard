import React from 'react';
import axios from 'axios';

class ReportGeneration extends React.Component {
    handleGenerateReport = () => {
        axios.get('/generate')
            .then(response => console.log(response))
            .catch(error => console.error(error));
    };

    render() {
        return (
            <div>
                <button onClick={this.handleGenerateReport}>Generate Report</button>
            </div>
        );
    }
}

export default ReportGeneration;
