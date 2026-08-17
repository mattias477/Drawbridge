using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace Drawbridge.App;

/// <summary>Visual emphasis used by a confirmation dialog.</summary>
public enum ConfirmationTone
{
    /// <summary>A destructive or potentially disruptive action.</summary>
    Danger,

    /// <summary>A safe action that benefits from acknowledgement.</summary>
    Information,
}

/// <summary>Dark confirmation dialog with an optional typed safety phrase.</summary>
public partial class ConfirmationWindow : Window
{
    private readonly string? _requiredPhrase;

    /// <summary>Initializes a new confirmation dialog.</summary>
    public ConfirmationWindow(
        string title,
        string message,
        string confirmLabel,
        string? requiredPhrase = null,
        ConfirmationTone tone = ConfirmationTone.Danger)
    {
        InitializeComponent();
        TitleText.Text = title;
        MessageText.Text = message;
        ConfirmButton.Content = confirmLabel;
        _requiredPhrase = requiredPhrase;
        PhrasePanel.Visibility = string.IsNullOrWhiteSpace(requiredPhrase) ? Visibility.Collapsed : Visibility.Visible;
        ConfirmButton.IsEnabled = string.IsNullOrWhiteSpace(requiredPhrase);
        PhraseHintText.Text = string.IsNullOrWhiteSpace(requiredPhrase)
            ? string.Empty
            : $"Type {requiredPhrase} to continue:";
        ApplyTone(tone);
        PreviewKeyDown += OnPreviewKeyDown;
    }

    /// <summary>Shows a confirmation dialog and returns whether it was accepted.</summary>
    public static bool Ask(
        Window owner,
        string title,
        string message,
        string confirmLabel,
        string? requiredPhrase = null,
        ConfirmationTone tone = ConfirmationTone.Danger)
    {
        var dialog = new ConfirmationWindow(title, message, confirmLabel, requiredPhrase, tone)
        {
            Owner = owner,
        };
        return dialog.ShowDialog() == true;
    }

    private void ApplyTone(ConfirmationTone tone)
    {
        if (tone != ConfirmationTone.Information)
        {
            return;
        }

        AccentBar.Background = (Brush)FindResource("PrimaryBrush");
        ConfirmationIconSurface.Background = new SolidColorBrush(Color.FromArgb(0x3D, 0x3B, 0x82, 0xF6));
        ConfirmationIconSurface.BorderBrush = new SolidColorBrush(Color.FromArgb(0x66, 0x3B, 0x82, 0xF6));
        ConfirmationIconText.Text = "i";
        ConfirmationIconText.Foreground = new SolidColorBrush(Color.FromRgb(0x8C, 0xB0, 0xFF));
        ConfirmationEyebrow.Text = "INFORMATION";
        ConfirmationEyebrow.Foreground = new SolidColorBrush(Color.FromRgb(0x86, 0xA8, 0xF8));
        ConfirmButton.Style = (Style)FindResource("PrimaryButton");
    }

    private void PhraseTextBox_OnTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) =>
        ConfirmButton.IsEnabled = string.Equals(PhraseTextBox.Text.Trim(), _requiredPhrase, StringComparison.Ordinal);

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Confirm_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
    }

    private void OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            DialogResult = false;
        }
        else if (e.Key == Key.Enter && ConfirmButton.IsEnabled)
        {
            DialogResult = true;
        }
    }
}
