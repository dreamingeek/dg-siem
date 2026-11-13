namespace DreaminGeek.Siem.Web.Components.Widgets;

/// <summary>Result line under a form: worked (green) or a problem to fix (red).</summary>
public sealed record Outcome(bool Ok, string Message);
