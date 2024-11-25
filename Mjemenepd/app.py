import os
import uuid
from datetime import datetime
import stripe
import threading
import webbrowser
from flask_wtf.csrf import CSRFError
from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FloatField, DecimalField
from wtforms.fields.datetime import DateField, TimeField
from wtforms.fields.simple import EmailField, TextAreaField
from wtforms.validators import InputRequired, Length, DataRequired, Email, EqualTo, ValidationError, NumberRange
from flask_bcrypt import Bcrypt, generate_password_hash
from flask_mail import Mail, Message
from flask_migrate import Migrate
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'Mthokozisi')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['WTF_CSRF_ENABLED'] = True
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mjemenetradings@gmail.com'
app.config['MAIL_PASSWORD'] = 'btje fyqc wypi hmza'
app.config['MAIL_DEFAULT_SENDER'] = 'mjemenetradings@gmail.com'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)
csrf = CSRFProtect(app)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

class Client(db.Model, UserMixin):
    __tablename__ = 'clients'
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    bookings = db.relationship('Booking', backref='client', lazy='dynamic')
    payment_detail = db.relationship('PaymentDetail', backref='client', uselist=False)


class Advisor(db.Model):
    __tablename__ = 'advisors'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    specialization = db.Column(db.String(100), nullable=False)
    bookings = db.relationship('Booking', backref='advisor', lazy='dynamic')


class Service(db.Model):
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    bookings = db.relationship('Booking', backref='service', lazy='dynamic')


class Admin(db.Model, UserMixin):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)


class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id'), nullable=False)
    advisor_id = db.Column(db.Integer, db.ForeignKey('advisors.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    appointment_type = db.Column(db.String(20), nullable=False)
    appointment_date = db.Column(db.Date, nullable=False)
    appointment_time = db.Column(db.Time, nullable=False)
    status = db.Column(db.String(20), default='Pending', nullable=False)
    invoice_number = db.Column(db.String(100), unique=True, nullable=False, default=lambda: f"INV-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}")

class PaymentDetail(db.Model):
    __tablename__ = 'payment_details'

    id = db.Column(db.Integer, primary_key=True)
    account_name = db.Column(db.String(255), nullable=False)
    account_number = db.Column(db.String(50), nullable=False)
    bank_name = db.Column(db.String(100), nullable=False)
    branch_name = db.Column(db.String(100), nullable=False)
    swift_code = db.Column(db.String(50), nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id'), nullable=False)
    def __repr__(self):
        return f"<PaymentDetail {self.account_name}>"

class RegisterForm(FlaskForm):
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password',validators=[InputRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        client = Client.query.filter_by(email=email.data).first()
        if client:
            raise ValidationError('Email is already in use.')

class ClientDeleteForm(FlaskForm):
    submit = SubmitField('Delete')

class AdminDeleteForm(FlaskForm):
    submit = SubmitField('Delete')

class LoginForm(FlaskForm):
    email = StringField('Email/Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AdvisorForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    specialization = StringField('Specialization', validators=[DataRequired()])
    submit = SubmitField('Submit')

class AddAdvisorForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    specialization = StringField('Specialization', validators=[DataRequired()])
    submit = SubmitField('Add Advisor')

class EditAdvisorForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    specialization = StringField('Specialization', validators=[DataRequired()])
    submit = SubmitField('Edit Advisor')

class AddServiceForm(FlaskForm):
    name = StringField('Service Name', validators=[DataRequired(message="Service name is required."), Length(max=150, message="Service name must be under 150 characters.")])
    description = TextAreaField('Description', validators=[DataRequired(message="Description is required."),Length(max=500, message="Description must be under 500 characters.")])
    price = DecimalField('Price', validators=[DataRequired(message="Price is required."),NumberRange(min=0, message="Price must be a positive value.")])
    submit = SubmitField('Add Service')

class EditServiceForm(FlaskForm):
    name = StringField('Service Name', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    price = DecimalField('Price', validators=[DataRequired()])
    submit = SubmitField('Update Service')

class DeleteServiceForm(FlaskForm):
    submit = SubmitField('Delete')

class AddAdminForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Username is required"),Length(min=4, max=25, message="Username must be between 4 and 25 characters")])
    password = PasswordField('Password', validators=[DataRequired(message="Password is required"),Length(min=6, message="Password must be at least 6 characters long") ])
    submit = SubmitField('Add Admin')

class ServiceForm(FlaskForm):
    name = StringField('Service Name', validators=[DataRequired()])
    description = StringField('Service Description', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    submit = SubmitField('Submit')

class BookingForm(FlaskForm):
    appointment_type = SelectField('Appointment Type', choices=[('Online', 'Online'), ('In-person', 'In-person')], validators=[DataRequired()])
    appointment_date = DateField('Appointment Date', format='%Y-%m-%d', validators=[DataRequired()])
    appointment_time = TimeField('Appointment Time', format='%H:%M', validators=[DataRequired()])
    service_id = SelectField('Service', coerce=int, validators=[DataRequired()])
    advisor_id = SelectField('Advisor', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Book Appointment')

class PaymentDetailsForm(FlaskForm):
    account_name = StringField('Account Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    bank_name = StringField('Bank Name', validators=[DataRequired()])
    branch_name = StringField('Branch Name', validators=[DataRequired()])
    swift_code = StringField('SWIFT Code', validators=[DataRequired()])
    account_type = StringField('Account Type', validators=[DataRequired()])
    submit = SubmitField('Delete')

class EditPaymentDetailsForm(FlaskForm):
    account_name = StringField('Account Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    bank_name = SelectField('Bank Name',choices=[('', 'Select a Bank'), ('absa', 'Absa'),('standard_bank', 'Standard Bank'),('capitec', 'Capitec')], validators=[DataRequired()])
    branch_name = StringField('Branch Name', validators=[DataRequired()])
    swift_code = StringField('SWIFT Code', validators=[DataRequired()])
    account_type = StringField('Account Type', validators=[DataRequired()])
    submit = SubmitField('Save')

class AddDetailsForm(FlaskForm):
    account_name = StringField('Account Name', validators=[DataRequired()])
    account_number = StringField('Account Number', validators=[DataRequired()])
    bank_name = SelectField('Bank Name',choices=[('', 'Select a Bank'), ('absa', 'Absa'), ('standard_bank', 'Standard Bank'),('capitec', 'Capitec')], validators=[DataRequired()])
    branch_name = StringField('Branch Name', validators=[DataRequired()])
    swift_code = StringField('SWIFT Code', validators=[DataRequired()])
    account_type = StringField('Account Type', validators=[DataRequired()])
    submit = SubmitField('Add Payment Details')

class UpdateBookingForm(FlaskForm):
    status = SelectField('Update Status', choices=[('Pending', 'Pending'),('Confirmed', 'Confirmed'),('Completed', 'Completed'),('Cancelled', 'Cancelled')],validators=[DataRequired()])
    submit = SubmitField('Update Status')


@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

@login_manager.user_loader
def load_user(user_id):
    client = Client.query.get(int(user_id))
    if client:
        return client

    admin = Admin.query.get(int(user_id))
    if admin:
        return admin

    return None

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Admin.query.filter_by(username=form.email.data).first()
        if not user:
            user = Client.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            if isinstance(user, Admin):
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('client_dashboard'))
        flash('Login failed. Check email and password.', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_client = Client(
            firstname=form.firstname.data,
            lastname=form.lastname.data,
            email=form.email.data,
            password=hashed_password
        )
        db.session.add(new_client)
        db.session.commit()

        msg = Message(
            'Welcome to Mjemene Tradings',
            recipients=[new_client.email],
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        msg.body = f"""
        Hello {new_client.firstname}\n\n

        Welcome to the Mjemene Tradings family!\n\n

        We’re thrilled to have you on board.\n 
        You can now log in to schedule your appointments and explore the wide range of services we offer,\n
        all designed to help you achieve your goals effortlessly.\n

        If you have any questions or need assistance,\n
        don’t hesitate to reach out—we’re here to support you every step of the way.\n

        Warm regards\n
        The Mjemene Tradings Team
        """
        try:
            mail.send(msg)
            flash('Registration successful. Please check your email for confirmation and then login.', 'success')
        except Exception as e:
            flash(f"An error occurred while sending the email: {str(e)}", 'danger')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/admin_dashboard', methods=['GET'])
@login_required
def admin_dashboard():
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    clients = Client.query.all()
    advisors = Advisor.query.all()
    services = Service.query.all()
    bookings = Booking.query.all()
    payments = PaymentDetail.query.all()

    return render_template('admin_dashboard.html', clients=clients, advisors=advisors, services=services, bookings=bookings)


@app.route('/client_dashboard', methods=['GET'])
@login_required
def client_dashboard():
    if not isinstance(current_user, Client):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    bookings = Booking.query.filter_by(client_id=current_user.id).all()
    payments = PaymentDetail.query.filter_by(client_id=current_user.id).all()

    return render_template('client_dashboard.html', bookings=bookings, payments=payments)


@app.route('/services_display', methods=['GET'])
@login_required
def services_display():
    services = Service.query.all()

    return render_template('services_display.html', services=services)


@app.route('/add_service', methods=['GET', 'POST'])
@login_required
def add_service():
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    form = AddServiceForm()
    if form.validate_on_submit():
        new_service = Service(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data
        )
        db.session.add(new_service)
        db.session.commit()
        flash('Service added successfully!', 'success')
        return redirect(url_for('services_display'))
    return render_template('add_service.html', form=form)

@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    service = Service.query.get_or_404(service_id)
    form = EditServiceForm(obj=service)

    if form.validate_on_submit():
        service.name = form.name.data
        service.description = form.description.data
        service.price = form.price.data
        db.session.commit()
        flash('Service updated successfully!', 'success')
        return redirect(url_for('services_display'))

    return render_template('edit_service.html', form=form, service=service)


@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def delete_service(id, new_service_id=None):
    services = Service.query.get_or_404(id)
    bookings = Booking.query.filter_by(service_id=id).all()
    for booking in bookings:
        booking.service_id = new_service_id

    db.session.delete(services)
    db.session.commit()
    flash('Service deleted successfully!', 'danger')
    return redirect(url_for('services_display'))


@app.route('/advisor_index', methods=['GET'])
@login_required
def advisor_index():
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    advisors = Advisor.query.all()  # Get all advisors from the database
    return render_template('advisor_index.html', advisors=advisors)

@app.route('/add_advisor', methods=['GET', 'POST'])
@login_required
def add_advisor():
    form = AddAdvisorForm()
    if form.validate_on_submit():
        new_advisor = Advisor(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            specialization=form.specialization.data
        )
        db.session.add(new_advisor)
        db.session.commit()
        flash('Advisor added successfully!', 'success')
        return redirect(url_for('advisor_index'))
    return render_template('add_advisor.html', form=form)


@app.route('/edit_advisor/<int:advisor_id>', methods=['GET', 'POST'])
def edit_advisor(advisor_id):
    advisor = Advisor.query.get_or_404(id)
    form = EditAdvisorForm(obj=advisor)

    if form.validate_on_submit():
        advisor.first_name = form.first_name.data
        advisor.last_name = form.last_name.data
        advisor.email = form.email.data
        advisor.specialization = form.specialization.data

        db.session.commit()
        flash('Advisor updated successfully!', 'success')
        return redirect(url_for('advisor_index'))

    return render_template('edit_advisor.html', form=form, advisor=advisor)


@app.route('/delete_advisor/<int:id>', methods=['GET', 'POST'])
def delete_advisor(id, new_advisor_id=None):
    advisor = Advisor.query.get_or_404(id)
    bookings = Booking.query.filter_by(advisor_id=id).all()
    for booking in bookings:
        booking.advisor_id = new_advisor_id

    db.session.delete(advisor)
    db.session.commit()
    flash('Advisor deleted successfully!', 'danger')
    return redirect(url_for('advisor_index'))


@app.route('/booking', methods=['GET', 'POST'])
@login_required
def booking():
    form = BookingForm()
    services = Service.query.all()
    advisors = Advisor.query.all()

    if not services:
        flash('No services available. Please contact support.', 'danger')
        return redirect(url_for('client_dashboard'))
    if not advisors:
        flash('No advisors available. Please contact support.', 'danger')
        return redirect(url_for('client_dashboard'))

    form.service_id.choices = [(service.id, f"{service.name} {service.price}") for service in services]
    form.advisor_id.choices = [(advisor.id, f"{advisor.first_name} {advisor.last_name}") for advisor in advisors]

    if form.validate_on_submit():
        try:
            new_booking = Booking(
                client_id=current_user.id,
                advisor_id=form.advisor_id.data,
                service_id=form.service_id.data,
                appointment_type=form.appointment_type.data,
                appointment_date=form.appointment_date.data,
                appointment_time=form.appointment_time.data,
                status='Pending'
            )
            db.session.add(new_booking)
            db.session.commit()

            new_booking.invoice_number = f"INV-{new_booking.id}-{uuid.uuid4().hex[:8]}"
            db.session.commit()

            service = Service.query.get(form.service_id.data)
            advisor = Advisor.query.get(form.advisor_id.data)
            client = current_user
            subject = 'Appointment Booking Confirmation'
            recipient_email = client.email
            body = f"""
            Hello {client.firstname},\n\n
            Your appointment has been successfully booked!\n\n
            Booking Details:\n
            - Invoice Number: {new_booking.invoice_number}\n
            - Service: {service.name}\n
            - Service Price: R{service.price}\n
            - Advisor: {advisor.first_name} {advisor.last_name}\n
            - Appointment Type: {form.appointment_type.data}\n
            - Appointment Date: {form.appointment_date.data.strftime('%Y-%m-%d')}\n
            - Appointment Time: {form.appointment_time.data.strftime('%H:%M')}\n
            Status: Pending\n
            Thank you for choosing our services.\n
            We look forward to assisting you!\n\n
            Best regards,\n
            The Mjemene Tradings Team
            """
            msg = Message(subject, recipients=[recipient_email])
            msg.body = body
            mail.send(msg)

            advisor_email = advisor.email
            subject_advisor = 'New Appointment Booking'
            body_advisor = f"""
            Hello {advisor.first_name},\n\n
            You have a new appointment booking!\n\n
            Booking Details:\n
            - Invoice Number: {new_booking.invoice_number}\n
            - Client: {client.firstname} {client.lastname}\n
            - Service: {service.name}\n
            - Service Price:R{service.price}\n
            - Appointment Type: {form.appointment_type.data}\n
            - Appointment Date: {form.appointment_date.data.strftime('%Y-%m-%d')}\n
            - Appointment Time: {form.appointment_time.data.strftime('%H:%M')}\n
            Status: Pending\n
            Please prepare for the appointment.\n\n
            Best regards,\n
            The Mjemene Tradings Team
            """
            msg_advisor = Message(subject_advisor, recipients=[advisor_email])
            msg_advisor.body = body_advisor
            mail.send(msg_advisor)

            flash('Your appointment has been booked successfully! Confirmation email has been sent to you and the advisor.', 'success')
            return redirect(url_for('my_bookings', booking_id=new_booking.id))

        except Exception as e:
            flash(f'Error while booking appointment: {str(e)}', 'danger')

    return render_template('booking.html', form=form)

@app.route('/update_booking_status/<int:booking_id>', methods=['GET', 'POST'])
@login_required
def update_booking_status(booking_id):
    booking = Booking.query.get_or_404(booking_id)

    form = UpdateBookingForm()

    if form.validate_on_submit():

        new_status = form.status.data
        booking.status = new_status
        db.session.commit()

        advisor = booking.advisor
        client = booking.client
        service = booking.service

        subject = 'Appointment Status Updated'
        recipient_email = client.email
        body = f"""
        Hello {client.firstname}\n\n

        Your appointment status has been updated.\n

        Booking Details:\n
        - Invoice Number: {booking.invoice_number}\n
        - Service: {service.name}\n
         Service Price: R{service.price}\n
        - Advisor: {advisor.first_name}  {advisor.last_name}\n
        - Appointment Type: {booking.appointment_type}\n
        - Appointment Date: {booking.appointment_date.strftime('%Y-%m-%d')}\n
        - Appointment Time: {booking.appointment_time.strftime('%H:%M')}\n
        New Status: {new_status}\n
        Thank you for choosing our services!\n
        Best regards,\n
        The Mjemene Tradings Team
        """
        msg = Message(subject, recipients=[recipient_email])
        msg.body = body
        mail.send(msg)

        advisor_email = advisor.email
        advisor_subject = 'Appointment Status Updated'
        advisor_body = f"""
        Hello {advisor.first_name}\n\n

        The status of a client appointment has been updated.\n

        Booking Details:\n
        - Client: {client.firstname}  {client.lastname}\n
        - Invoice number: {booking.invoice_number}\n
        - Service: {service.name}\n
         Service Price: R{service.price}\n
        - Appointment Type: {booking.appointment_type}\n
        - Appointment Date: {booking.appointment_date.strftime('%Y-%m-%d')}\n
        - Appointment Time: {booking.appointment_time.strftime('%H:%M')}\n

        New Status: {new_status}\n

        Please prepare accordingly.\n

        Best regards,\n
        The Mjemene Tradings Team
        """
        advisor_msg = Message(advisor_subject, recipients=[advisor_email])
        advisor_msg.body = advisor_body
        mail.send(advisor_msg)

        flash('Booking status updated and emails have been sent to the client and advisor.', 'success')
        return redirect(url_for('bookings'))

    return render_template('update_booking_status.html', booking=booking, form=form)

@app.route('/delete_booking/<int:booking_id>', methods=['GET', 'POST'])
def delete_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    db.session.delete(booking)
    db.session.commit()

    flash('Booking deleted successfully!', 'success')

    return redirect(url_for('bookings'))

@app.route('/bookings', methods=['GET'])
@login_required
def bookings():
    bookings = Booking.query.all()
    return render_template('bookings.html', bookings=bookings)

@app.route('/payment', methods=['GET'])
@login_required
def payment():
    if isinstance(current_user, Admin):
        flash('Admins cannot view client payment details.', 'danger')
        return redirect(url_for('admin_dashboard'))

    client_payment_details = PaymentDetail.query.filter_by(client_id=current_user.id).first()

    if not client_payment_details:
        company_account_details = PaymentDetail.query.all()
        flash('No payment details found for this client.', 'danger')
        return redirect(url_for('client_dashboard'))

    return render_template('payment.html', payment=client_payment_details)


@app.route('/payment_index', methods=['GET'])
@login_required
def payment_index():
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    company_account_details = PaymentDetail.query.all()
    form = AddDetailsForm()
    return render_template('payment_index.html', details=company_account_details, form=form)


@app.route('/add_payment', methods=['GET', 'POST'])
@login_required
def add_payment():
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    form = AddDetailsForm()

    if form.validate_on_submit():

        client = Client.query.first()
        if not client:
            flash('No client found. Please ensure a client exists before adding payment details.', 'danger')
            return redirect(url_for('add_payment'))

        new_payment = PaymentDetail(
            account_name=form.account_name.data,
            account_number=form.account_number.data,
            bank_name=form.bank_name.data,
            branch_name=form.branch_name.data,
            swift_code=form.swift_code.data,
            account_type=form.account_type.data,
            client_id=client.id
        )
        db.session.add(new_payment)
        db.session.commit()

        flash('Payment details added successfully!', 'success')
        return redirect(url_for('payment_index'))

    return render_template('add_payment.html', form=form)


@app.route('/edit_payment/<int:payment_id>', methods=['GET', 'POST'])
@login_required
def edit_payment(payment_id):
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    payment_detail = PaymentDetail.query.get_or_404(payment_id)
    form = AddDetailsForm(obj=payment_detail)

    if form.validate_on_submit():
        payment_detail.account_name = form.account_name.data
        payment_detail.account_number = form.account_number.data
        payment_detail.bank_name = form.bank_name.data
        payment_detail.branch_name = form.branch_name.data
        payment_detail.swift_code = form.swift_code.data
        payment_detail.account_type = form.account_type.data
        db.session.commit()

        flash('Payment details updated successfully!', 'success')
        return redirect(url_for('payment_index'))

    return render_template('edit_payment.html', form=form, payment=payment_detail)

@app.route('/delete_payment/<int:payment_detail_id>', methods=['POST'])
@login_required
def delete_payment(payment_detail_id):
    if not isinstance(current_user, Admin):
        flash('Access denied.', 'danger')
        return redirect(url_for('payment_index'))
    payment_detail = PaymentDetail.query.get_or_404(payment_detail_id)
    db.session.delete(payment_detail)
    db.session.commit()
    flash('Payment details deleted successfully!', 'success')
    return redirect(url_for('payment_index'))

@app.route('/my_bookings', methods=['GET'])
@login_required
def my_bookings():
    bookings = Booking.query.filter_by(client_id=current_user.id).all()

    return render_template('my_bookings.html', bookings=bookings)

@app.route('/privacy', methods=['GET'])
def privacy():
    return render_template('privacy.html')

@app.route('/services', methods=['GET'])
def services():
    return render_template('services.html')

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/view_clients', methods=['GET'])
@login_required
def view_clients():
    clients = Client.query.all()
    return render_template('view_clients.html', clients=clients)


@app.route('/delete_client/<int:id>', methods=['POST'])
@login_required
def delete_client(id):
    try:
        if not isinstance(current_user, Admin):
            flash('Access denied.', 'danger')
            return redirect(url_for('view_clients'))

        client_to_delete = Client.query.get_or_404(id)

        for booking in client_to_delete.bookings:
            db.session.delete(booking)

        if client_to_delete.payment_detail:
            db.session.delete(client_to_delete.payment_detail)

        db.session.delete(client_to_delete)
        db.session.commit()

        flash('Client deleted successfully!', 'success')
        return redirect(url_for('view_clients'))

    except CSRFError:
        flash('CSRF token missing or incorrect. Please try again.', 'danger')
        return redirect(url_for('view_clients'))


@app.route('/admin_index')
@login_required
def admin_index():
    admins = Admin.query.all()
    return render_template('admin_index.html', admins=admins)

@app.route('/add_admin', methods=['GET', 'POST'])
@login_required
def add_admin():
    form = AddAdminForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        existing_admin = Admin.query.filter_by(username=username).first()
        if existing_admin:
            flash('Username is already registered.', 'danger')
            return redirect(url_for('add_admin'))

        hashed_password = generate_password_hash(password)
        new_admin = Admin(username=username, password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()

        flash('New admin added successfully!', 'success')
        return redirect(url_for('admin_index'))

    return render_template('add_admin.html', form=form)


@app.route('/delete_admin/<int:id>', methods=['POST'])
@login_required
def delete_admin(id):
    try:
        if not isinstance(current_user, Admin):
            flash('Access denied.', 'danger')
            return redirect(url_for('admin_index'))

        admin_to_delete = Admin.query.get_or_404(id)
        if admin_to_delete:
            db.session.delete(admin_to_delete)

        db.session.delete(admin_to_delete)
        db.session.commit()

        flash('Client deleted successfully!', 'success')
        return redirect(url_for('admin_index'))

    except CSRFError:
        flash('CSRF token missing or incorrect. Please try again.', 'danger')
        return redirect(url_for('admin_index'))


with app.app_context():
    db.create_all()

def open_browser():
    webbrowser.open_new('http://127.0.0.1:5000/')

if __name__ == "__main__":
    threading.Timer(1, open_browser).start()
    app.run(debug=True)
