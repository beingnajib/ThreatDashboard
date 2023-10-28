import React, { Component } from 'react';
import axios from 'axios';

class AnalyzeData extends Component {
    handleAnalyzeData = () => {
        axios.get('/analyze/')
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
                <button onClick={this.handleAnalyzeData}>Analyze Data</button>
            </div>
        );
    }
}

export default AnalyzeData;
