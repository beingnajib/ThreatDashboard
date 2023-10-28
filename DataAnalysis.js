import React from 'react';
import axios from 'axios';
import { Bar } from 'react-chartjs-2';

class DataAnalysis extends React.Component {
    state = {
        data: []
    };

    componentDidMount() {
        axios.get('/analyze')
            .then(response => this.setState({ data: response.data }))
            .catch(error => console.error(error));
    }

    render() {
        return (
            <div>
                <Bar data={this.state.data} />
            </div>
        );
    }
}

export default DataAnalysis;
