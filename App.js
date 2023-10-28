import React, { Component } from 'react';
import ImportData from './ImportData';
import AnalyzeData from './AnalyzeData';
import GenerateReport from './GenerateReport';

class App extends Component {
    render() {
        return (
            <div>
                <ImportData />
                <AnalyzeData />
                <GenerateReport />
            </div>
        );
    }
}

export default App;
