using System.Windows;
using System.Windows.Input;

namespace Drawbridge.App;

/// <summary>Dark confirmation dialog with an optional typed safety phrase.</summary>
public partial class ConfirmationWindow : Window
{
    private readonly string? _requiredPhrase;

    /// <summary>Initializes a new confirmation dialog.</summary>
    public ConfirmationWindow(string title, string message, string confirmLabel, string? requiredPhrase = null)
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
        PreviewKeyDown += OnPreviewKeyDown;
    }

    /// <summary>Shows a confirmation dialog and returns whether it was accepted.</summary>
    public static bool Ask(Window owner, string title, string message, string confirmLabel, string? requiredPhrase = null)
    {
        var dialog = new ConfirmationWindow(title, message, confirmLabel, requiredPhrase)
        {
            Owner = owner,
        };
        return dialog.ShowDialog() == true;
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
