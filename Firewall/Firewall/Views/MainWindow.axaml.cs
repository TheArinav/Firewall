using System;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace Firewall.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        this.PropertyChanged += MainWindow_PropertyChanged;

    }
    private void TitleBar_PointerPressed(object sender, Avalonia.Input.PointerPressedEventArgs e)
    {
        if (e.GetCurrentPoint(this).Properties.IsLeftButtonPressed)
            BeginMoveDrag(e);
    }
    private void Minimize_Click(object sender, RoutedEventArgs e)
    {
        this.WindowState = WindowState.Minimized;
    }

    private void MaximizeRestore_Click(object sender, RoutedEventArgs e)
    {
        this.WindowState = this.WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        this.Close();
    }
    private void MainWindow_PropertyChanged(object? sender, AvaloniaPropertyChangedEventArgs e)
    {
        if (e?.Property != Window.WindowStateProperty) return;
        var state = (WindowState)e.NewValue!;
        MainBorder.CornerRadius = state == WindowState.Maximized ? new CornerRadius(0) : new CornerRadius(5);
    }
}