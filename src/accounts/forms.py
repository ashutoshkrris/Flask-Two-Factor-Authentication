from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Length, InputRequired

from src.accounts.models import User


class RegisterForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=6, max=40)]
    )
    password = PasswordField(
        "Password", validators=[DataRequired(), Length(min=6, max=25)]
    )
    confirm = PasswordField(
        "Repeat password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )

    def validate(self, extra_validators):
        initial_validation = super(RegisterForm, self).validate(extra_validators)
        if not initial_validation:
            return False
        user = User.query.filter_by(username=self.username.data).first()
        if user:
            self.username.errors.append("Username already registered")
            return False
        if self.password.data != self.confirm.data:
            self.password.errors.append("Passwords must match")
            return False
        return True


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class TwoFactorForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[
                      InputRequired(), Length(min=6, max=6)])
