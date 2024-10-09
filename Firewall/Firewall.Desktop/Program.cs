using System;
using Avalonia;
using Avalonia.OpenGL;

namespace Firewall.Desktop;

sealed class Program
{
    // Initialization code. Don't use any Avalonia, third-party APIs or any
    // SynchronizationContext-reliant code before AppMain is called: things aren't initialized
    // yet and stuff might break.
    [STAThread]
    public static void Main(string[] args) => BuildAvaloniaApp()
        .StartWithClassicDesktopLifetime(args);

    // Avalonia configuration, don't remove; also used by visual designer.
    private static AppBuilder BuildAvaloniaApp()
    {
        return AppBuilder.Configure<App>()
            .UseSkia()
            .UsePlatformDetect()
            .With(new X11PlatformOptions
            {
                OverlayPopups = true,
                UseDBusMenu = false,
                UseDBusFilePicker = false,
                EnableIme = true,
                EnableInputFocusProxy = true,
                EnableSessionManagement = true,
                RenderingMode = new[]
                {
                    X11RenderingMode.Software,
                    X11RenderingMode.Egl,
                },
                ShouldRenderOnUIThread = true,
                GlProfiles = new[]
                {
                    new GlVersion(GlProfileType.OpenGL, 3, 2), 
                    new GlVersion(GlProfileType.OpenGLES, 3, 0) 
                },
                GlxRendererBlacklist = new[]
                {
                    "llvmpipe" 
                },
                WmClass = "FirewallApp",
                EnableMultiTouch = false,
                UseRetainedFramebuffer = false
            }).With(new Win32PlatformOptions
            {
                OverlayPopups = true, // Enable overlay popups
                RenderingMode = new[]
                {
                    Win32RenderingMode.AngleEgl // Fallback to software rendering
                },
                ShouldRenderOnUIThread = true, // Enable rendering on the UI thread
                DpiAwareness = Win32DpiAwareness.PerMonitorDpiAware // Set DPI awareness
            })
            .WithInterFont()
            .LogToTrace();
    } 
}