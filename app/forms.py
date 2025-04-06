from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired

class ConfigForm(FlaskForm):
    platform = SelectField("Platform", choices=[("github", "GitHub"), ("gitlab", "GitLab")])
    base_url = StringField("Repo Base URL", validators=[DataRequired()])
    token = StringField("Repo Token", validators=[DataRequired()])
    defectdojo_url = StringField("DefectDojo URL", validators=[DataRequired()])
    defectdojo_token = StringField("DefectDojo Token", validators=[DataRequired()])
    repo_list = TextAreaField("Repo List (one per line)", validators=[DataRequired()])
    submit = SubmitField("Save & Trigger Scan")
