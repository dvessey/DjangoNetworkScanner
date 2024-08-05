from django import forms

class ScanForm(forms.Form):
    ip = forms.CharField(help_text="192.168.0.1/24")