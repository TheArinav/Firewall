using System;
using System.Collections.Generic;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Firewall.Views.SecondryViews;

namespace Firewall.Views;

public enum CurrentSubView
{
    None,
    FirewallConfig,
    ProtocolConfig,
    ConnectionsConfig
}

public partial class MainView : UserControl
{
    private Stack<CurrentSubView> History { get; set; }
    private Queue<CurrentSubView> Future { get; set; }
    private CurrentSubView SubView { get; set; } = CurrentSubView.None;
    public MainView()
    {
        this.InitializeComponent();
        this.History = new Stack<CurrentSubView>();
        this.Future = new Queue<CurrentSubView>();
        this.OnHistoryChanged();
    }

    private void PushHistory(CurrentSubView view)
    {
        this.Future.Clear();
        this.History.Push(view);
        this.OnHistoryChanged();
    }
    private CurrentSubView PopHistory()
    {
        var tmp = this.History.Pop();
        this.Future.Enqueue(this.SubView);
        this.OnHistoryChanged();
        return tmp;
    }

    private CurrentSubView PopFuture()
    {
        var tmp = this.Future.Dequeue();
        this.History.Push(this.SubView);
        this.OnHistoryChanged();
        return tmp;
    }

    private void OnHistoryChanged()
    {
        this.UndoBttn.IsEnabled = History.Count != 0;
        this.RedoBttn.IsEnabled = Future.Count != 0;
    }

    private void HandleViewChange()
    {
        this.View.Content = this.SubView switch
        {
            CurrentSubView.None => null,
            CurrentSubView.FirewallConfig => new FirewallConfigView(),
            _ => throw new NotImplementedException()
        };
    }

    public void OnFirewallConfigButtonClick(object? sender, RoutedEventArgs e)
    {
        this.PushHistory(this.SubView);
        this.SubView = SubView == CurrentSubView.FirewallConfig ? CurrentSubView.None : CurrentSubView.FirewallConfig;
        this.HandleViewChange();
    }

    public void OnUndoBttnClick(object? sender, RoutedEventArgs e)
    {
        this.SubView = PopHistory();
        this.HandleViewChange();
    }

    public void OnRedoBttnClick(object? sender, RoutedEventArgs e)
    {
        this.SubView = this.PopFuture();
        this.HandleViewChange();
    }
}