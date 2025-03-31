package org.example;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;

import javax.swing.*;
import java.util.List;

public class CreateChart {

    public static void createChart(List<Pair<Integer, Long>> results){
        DefaultCategoryDataset timeData = new DefaultCategoryDataset();
        DefaultCategoryDataset inputData = new DefaultCategoryDataset();

        // going through list and adding to dataSets (time, inputs)
        for (int index = 0; index < results.size(); index++){
            int bits = 8 + index*2;
            Pair<Integer, Long> result = results.get(index);
            timeData.addValue(result.getValue(), "Time", Integer.toString(bits));
            inputData.addValue(result.getKey(), "Inputs", Integer.toString(bits));
        }

        JFreeChart timeChart = ChartFactory.createLineChart(
                "Digest Size vs. Collision Time",
                "Digest Size (bits)",
                "Collision Time (ms)",
                timeData,
                PlotOrientation.VERTICAL,
                true, true, false
        );

        JFreeChart inputChart = ChartFactory.createLineChart(
                "Digest Size vs Number of Inputs",
                "Digest Size (bits)",
                "Number of Inputs",
                inputData,
                PlotOrientation.VERTICAL,
                true, true, false);

        JFrame frame = new JFrame("Collision Charts");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BoxLayout(frame.getContentPane(), BoxLayout.Y_AXIS));

        // Add charts to the window
        frame.add(new ChartPanel(timeChart));
        frame.add(new ChartPanel(inputChart));

        // Display the window.
        frame.pack();
        frame.setVisible(true);
    }
}
