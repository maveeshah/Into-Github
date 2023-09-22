import frappe
from frappe.website.utils import is_signup_disabled
from frappe import _
import re
from frappe.utils import today, add_months, escape_html
from http import HTTPStatus

# function for validating the email addresses
def is_valid_email(email):
	pattern = r'^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$'
	return re.match(pattern, email) is not None

# function to generate responses
def _create_response(http_status_code, success_key, message, data=None):
	if data:
		message = data
	frappe.local.response.update({
		"data": {
		"success_key": success_key,
		"message":message
		},
		"http_status_code": http_status_code
	})

def generate_keys(user):
	user_details = frappe.get_doc('User', user)
	api_secret = frappe.generate_hash(length=15)
	api_keysss = user_details.api_key
	if not user_details.api_key:
		api_key = frappe.generate_hash(length=15)
		api_keysss = api_key
		user_details.api_key = api_key

	user_details.api_secret = api_secret
	user_details.save()

	return api_secret , api_keysss

def _expire_otp(code_doc):
    code_doc.used_already = 1
    code_doc.status = "Expired"
    code_doc.save(ignore_permissions=True)
    code_doc.submit()

def save_image_as_attachment(file_name, image_data):
    file_data = frappe.utils.data.base64_to_binary(image_data)
    file_doc = frappe.get_doc({
        "doctype": "File",
        "file_name": file_name,
        "content": file_data,
        "is_private": 0,  # Adjust privacy settings as needed
    })
    file_doc.insert()

def create_order(email, order_info, payment_info):
	try:
		if frappe.db.exists("User", {"email": email}):
			user = frappe.get_doc("User", {"email": email})
			if user:
				if frappe.db.exists("Customer", {"email": email, "account_manager": email}):
					customer = frappe.get_doc("Customer", {"email": email, "account_manager": email})
					if customer:
						if customer.disabled:
							return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Customer with this email and information is already registered but disabled.")

						cus_name = frappe.db.get_value("Customer", {"email": email, "account_manager": email}, "customer_name")
						order = {
							"customer": cus_name,
							"order_type": "Sales",
							"items": []
						}
						payment_method = payment_info.get("payment_option")
						if payment_info and not payment_method:
							return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Please provide payment method information.")
						payment_terms_template = ''
						if payment_method == "flexi_payment":
							payment_terms_template = "6 Months Installments"
							# Calculate delivery date as today's date plus 30 months
							delivery_date = add_months(today(), 30)
							for item in order_info:
								item_code = item.get("item_code")
								parts = item.get("parts")
								package_name = item.get("package_name")

								if item_code and parts:
									order_item = {
									"item_code": item_code,
									"qty": parts,
									"package_name": package_name,
									"delivery_date": delivery_date
									}
									order["items"].append(order_item)

							# Create a new Sales Order document
							new_order = frappe.get_doc({
								"doctype": "Sales Order",
								"customer": cus_name,
								"payment_terms_template": payment_terms_template,
								"order_type": "Sales",
								"items": order["items"],
							})

							# Insert the new order into the database
							new_order.flags.ignore_permissions = True
							new_order.insert()
							new_order.submit()

							return _create_response(HTTPStatus.OK, "success", 
			       										"Order has been recorded and is in process. Proceed to clear due amounts"
			       										,{"order_no":new_order.name})
						else:
							# Calculate delivery date as today's date plus 30 months
							delivery_date = add_months(today(), 30)
							for item in order_info:
								item_code = item.get("item_code")
								parts = item.get("parts")
								package_name = item.get("package_name")

								if item_code and parts:
									order_item = {
									"item_code": item_code,
									"qty": parts,
									"package_name": package_name,
									"delivery_date": delivery_date
									}
									order["items"].append(order_item)

							# Create a new Sales Order document
							new_order = frappe.get_doc({
								"doctype": "Sales Order",
								"customer": cus_name,
								"order_type": "Sales",
								"items": order["items"],
							})

							# Insert the new order into the database
							new_order.flags.ignore_permissions = True
							new_order.insert()

							new_order.submit()
							# Create a new Payment Entry document

							email = email
							# payment_amount = payment_info.get("paid_amount") if payment_info.get("payment_option") == "flexi_payment"else 3000
							payment_amount = payment_info.get("paid_amount") if payment_info.get("paid_amount") else 3000
							order_name = new_order.name  # The name of the sales order to link the payment to
							paid_via = "Cash"
							payment_entry = frappe.get_doc({
								"doctype": "Payment Entry",
								"payment_type": "Receive",
								"party_type": "Customer",
								"party": customer.name,
								"posting_date": frappe.utils.today(),
								"paid_amount": payment_amount,
								"reference_doctype": "Sales Order",
								"received_amount": payment_amount,
								"reference_name": order_name,
								"mode_of_payment": paid_via,
								"paid_to":"Cash - E",
								"references": [
									{
										"reference_doctype": "Sales Order",
										"reference_name": order_name,
										"allocated_amount": payment_amount
									}
								]
							})

							# Insert the new payment entry into the database
							payment_entry.flags.ignore_permissions = True
							payment_entry.insert(ignore_permissions=True)
							payment_entry.submit()

							return _create_response(HTTPStatus.OK, "success", """Congratulations your order is completed.
			       																	Payment is also cleared, You'll be allocated a ruminant as per availability."""
			       																	,{"order_no":new_order.name})
							# make_payment_entry(email = email,order_name = new_order.name,payment_amount = payment_info.get("paid_amount"),paid_via = "Cash")
							# create_invoice(email,order_info,new_order)

							return _create_response(HTTPStatus.OK, "success", "Congratulations your order is completed.",{"order_no":new_order.name})

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred while processing the order: {}".format(str(e)))

# def create_invoice(email, order_info,new_order):
# 	try:
# 		cus_name = frappe.db.get_value("Customer", {"email": email, "account_manager": email}, "customer_name")

# 		# Calculate delivery date as today's date plus 30 months
# 		delivery_date = add_months(today(), 30)
# 		invoice = {
# 			"customer": cus_name,
# 			"due_date": delivery_date,
# 			"items": []
# 		}

# 		for item in order_info:
# 			item_code = item.get("item_code")
# 			parts = item.get("parts")
# 			package_name = item.get("package_name")

# 			if item_code and parts:

# 				invoice_item = {
# 					"item_code": item_code,
# 					"qty": parts,
# 					"sales_order": new_order.name,
# 					"delivered_quantity": parts,
# 					"package_name": package_name,
# 				}
# 				invoice["items"].append(invoice_item)

# 		# Create a new Sales Invoice document
# 		new_invoice = frappe.get_doc({
# 			"doctype": "Sales Invoice",
# 			"customer": cus_name,
# 			"order_type": "Sales",
# 			"items": invoice["items"],
# 			"allocate_advances_automatically": 1,
# 			"only_include_allocated_payments":1
# 		})

# 		# Insert the new invoice into the database
# 		new_invoice.flags.ignore_permissions = True
# 		new_invoice.insert()
# 		new_invoice.submit()

# 		return _create_response(HTTPStatus.OK, "success", "Order Completed.",{"invoice_no":new_invoice.name})

# 	except Exception as e:
# 		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred while processing the order: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def sign_up(**kwargs):
    if frappe.request.method != "POST":
        return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", _("Method Not Allowed"))

    email = kwargs.get("email")
    first_name = kwargs.get("first_name")
    last_name = kwargs.get("last_name")
    mobile_no = kwargs.get("mobile_no")

    if is_signup_disabled():
        return _create_response(HTTPStatus.FORBIDDEN, "error", _("Sign Up is disabled"))

    if not is_valid_email(email):
        return _create_response(HTTPStatus.BAD_REQUEST, "error", _("Invalid email format"))

    user = frappe.db.get("User", {"email": email})
    if user:
        if user.enabled:
            return _create_response(HTTPStatus.CONFLICT, "error", _(f"This email is not available. '{email}'. Please use another"))
        else:
            return _create_response(HTTPStatus.CONFLICT, "error", _(f"This email is not available. '{email}'. Please use another"))
    else:
        mobile_user = frappe.db.get("User", {"mobile_no": mobile_no})
        if mobile_user:
            if mobile_user.enabled:
                return _create_response(HTTPStatus.CONFLICT, "error", _("Duplicate Mobile entry"))
            else:
                return _create_response(HTTPStatus.CONFLICT, "error", _("Duplicate Mobile entry and User is disabled"))

        if frappe.db.get_creation_count("User", 60) > 300:
            return _create_response(HTTPStatus.TOO_MANY_REQUESTS, "error",
                                    _("Too many users signed up recently, so the registration is disabled. "
                                      "Please try back in an hour"))

        user = frappe.get_doc(
            {
                "doctype": "User",
                "email": email,
                "first_name": escape_html(first_name),
                "last_name": escape_html(last_name),
                "mobile_no": mobile_no,
                "enabled": 1,
                "role_profile_name": 'Customer',
                "send_welcome_email": 0,
                "user_type": "System User",
            }
        )
        user.flags.ignore_permissions = True
        user.flags.ignore_password_policy = True
        user.insert()

        return _create_response(HTTPStatus.CREATED, "success", _("Please head over to the 1st time login page."))

@frappe.whitelist(allow_guest=True)
def send_otp(email):
	if frappe.request.method != "GET":
		return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")

	if frappe.db.exists("User", email):
		if frappe.db.exists("User Verification Code",{"ref_docname":email}):
			if frappe.db.count("User Verification Code",{"ref_docname":email}) > 3:
				return _create_response(HTTPStatus.TOO_MANY_REQUESTS, "error", "You've requested code too many times.")

		user = frappe.get_doc("User", {"email": email})

		code = frappe.generate_hash(length=7)
		code_verify = frappe.new_doc("User Verification Code")
		code_verify.ref_doctype = "User"
		code_verify.ref_docname = user.name
		code_verify.status = "Valid"
		code_verify.otp = code
		code_verify.save(ignore_permissions=True)
		subject = _("Verify Your Email")
		message = f"Your verification code is: {code}. Please do not share it with anyone"
		recipient = email

		frappe.sendmail(recipients=[recipient], subject=subject, message=message, now=True)

		return _create_response(HTTPStatus.OK, "success", "Please head over to your email for the OTP.")
	else:
		return _create_response(HTTPStatus.NOT_FOUND, "error", "No user linked with the email.")

@frappe.whitelist(allow_guest=True)
def set_initial_password(email, verification_code, new_password):
    if frappe.request.method != "POST":
        return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")
    try:
        pwd = new_password
        user = frappe.get_doc("User", {"email": email})
        code_doc = frappe.get_doc("User Verification Code", {"ref_docname": email})

        if not user:
            return _create_response(HTTPStatus.NOT_FOUND, "error", "No user linked with the email.")

        if not code_doc:
            return _create_response(HTTPStatus.NOT_FOUND, "error", "No OTP linked with the email.")

        user_otp = frappe.db.sql(
            f"""SELECT otp, status FROM `tabUser Verification Code`
                WHERE ref_doctype = 'User'
                AND ref_docname = '{email}'
                ORDER BY creation DESC
                LIMIT 1""",
            as_dict=True
        )[0]

        if not user_otp:
            return _create_response(HTTPStatus.NOT_FOUND, "error", "No OTP found.")
        if user_otp.status == "Valid" and user_otp.otp == verification_code:
            user.new_password = new_password
            user.save(ignore_permissions=True)
            _expire_otp(code_doc)
            frappe.db.commit()
            return _create_response(HTTPStatus.OK, "success", "Password set successfully")

        elif user_otp.status == "Expired":
            return _create_response(HTTPStatus.NOT_FOUND, "error", "OTP has expired. Get another one.")
        else:
            return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Invalid verification code.")

    except Exception as e:
        return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: " + str(e))

@frappe.whitelist(allow_guest=True)
def verify_login(email, password, role= None):
	if frappe.request.method != "POST":
		return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")
	try:
		# Validate the email address
		if not email or not frappe.utils.validate_email_address(email):
			_create_response(HTTPStatus.UNAUTHORIZED, "error", "Invalid Email address!")
			return

		# Get the user document for the given email
		if not frappe.db.exists("User", {"email": email}):
			return _create_response(HTTPStatus.NOT_FOUND, "error", "User not found")
			

		user = frappe.get_doc("User", {"email": email})

		# Check if the user account is enabled
		if not user.enabled:
			return _create_response(HTTPStatus.UNAUTHORIZED, "error", "User is disabled!")
		if role:
			if not user.role_profile_name == "Customer" and role == "Customer":
				return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Please Head over to the login of Breeder/Feedlot!")
			else:
				role_array = role.split("/")
				if user.role_profile_name not in role_array:
					return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Please Head over to the login of Customer!")
			

		login_manager = frappe.auth.LoginManager()
		login_manager.authenticate(user=email, pwd=password)
		login_manager.post_login()

	except frappe.exceptions.AuthenticationError:
		return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Authentication Error!")

	api_generate = generate_keys(frappe.session.user)
	user = frappe.get_doc('User', frappe.session.user)
	response_dict = {}
	if user.role_profile_name == "Customer":

		response_dict["role"] = "Customer"
		response_dict["email"] = user.name
		return _create_response(HTTPStatus.OK, "success","Authentication success", {"user_info" :response_dict})

		# exclude_fields = ["creation", "modified","amended_from", "modified_by", "owner","docstatus","idx","naming_series","_user_tags","_comments","_assign","_liked_by","_seen"]
		# customer_fields = [field.fieldname for field in frappe.get_meta("Customer").fields if field.fieldname not in exclude_fields and field.fieldtype not in ["Tab Break","Section Break","Column Break"]]
		# customer_fields.append("name")
		# customer_prof = frappe.get_all("Customer",
		# 								filters={"username": email},
		# 								fields=[field for field in breeder_fields])
		# response_dict["role"] = "Customer"
		# response_dict["profile_info"] = customer_prof
		# _create_response(HTTPStatus.OK, "success", "Authentication success",
		# 				{"user_info":response_dict }
		# )
	if user.role_profile_name == "Breeder":
		exclude_fields = ["creation", "modified","amended_from", "modified_by", "owner","docstatus","idx","naming_series","_user_tags","_comments","_assign","_liked_by","_seen"]
		breeder_fields = [field.fieldname for field in frappe.get_meta("Breeder").fields if field.fieldname not in exclude_fields and field.fieldtype not in ["Tab Break","Section Break","Column Break"]]
		breeder_fields.append("name")
		breeder_prof = frappe.get_all("Breeder",
										filters={"username": email},
										fields=[field for field in breeder_fields])
		response_dict["role"] = "Breeder"
		response_dict["profile_info"] = breeder_prof
		return _create_response(HTTPStatus.OK, "success","Authentication success", {"user_info" :response_dict})

	if user.role_profile_name == "Feedlot":
		exclude_fields = ["creation", "modified", "modified_by", "owner","docstatus","idx","naming_series","_user_tags","_comments","_assign","_liked_by","_seen"]
		feedlot_fields = [field.fieldname for field in frappe.get_meta("Feedlot").fields if field.fieldname not in exclude_fields and field.fieldtype not in ["Tab Break","Section Break","Column Break"]]
		feedlot_fields.append("name")
		feedlot_prof = frappe.get_all("Feedlot",
										filters={"username": email},
										fields=[field for field in feedlot_fields])

		name = feedlot_prof[0]["breeder_id"]
		feed_id = feedlot_prof[0]["name"]
		feedlot_prof[0]["name"] = name
		feedlot_prof[0]["feedlot_id"] = feed_id
		response_dict["role"] = "Feedlot"
		response_dict["profile_info"] = feedlot_prof
		return _create_response(HTTPStatus.OK, "success","Authentication success", {"user_info" :response_dict})
	
@frappe.whitelist(allow_guest=True)
def get_states_cities_and_countries(**kwargs):
	try:
		if frappe.request.method == "GET":
			# Validate user_info and customer_info parameters
			request_for = kwargs.get('requesting')
			if not request_for:
				return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Specify what you are looking for: Countries, States, or Cities.")

			if request_for == "Country":
				countries = frappe.get_all("Country")
				return _create_response(HTTPStatus.OK, "success", "", {
					"countries": [country.name for country in countries]
				})

			elif request_for == "States":
				country = kwargs.get('country')
				if country:
					states = frappe.get_all("States", filters={"country": country})
					return _create_response(HTTPStatus.OK, "success", "", {
						"states": [state.name for state in states]
					})
				else:
					return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Please provide the 'country' parameter.")

			elif request_for == "City":
				country = kwargs.get('country')
				state = kwargs.get('state')
				if country and state:
					cities = frappe.get_all("City", filters={"country": country, "state": state})
					return _create_response(HTTPStatus.OK, "success", "", {
						"cities": [city.name for city in cities]
					})
				else:
					return _create_response(HTTPStatus.FORBIDDEN, "error", "Please provide the 'country' and 'state' parameters.")

			else:
				return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Invalid value for 'requesting' parameter. Expected 'Country', 'States', or 'City'.")
		else:
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")

	except:
		# Handle any exceptions here
		return _create_response(HTTPStatus.UNAUTHORIZED, "error", "An error occurred while processing the request.")

@frappe.whitelist(allow_guest=True)
def create_sales_order(**kwargs):
    try:
        if frappe.request.method != "POST":
            sample_request = {
                        "user_info": {
                            "email": "waqarniazi51@gmail.com",
                            "first_name": "waqar",
                            "last_name": "niazi",
                            "mobile_no": "123-456-7890"
                        },
                        "customer_info": {
                            "customer_name": "Acme Corp",
                            "customer_email": "waqarniazi51@gmail.com",
                            "customer_phone": "123-456-7890",
                            "salutation": "Mr",
                            "customer_group": "Individual",
                            "territory": "All Territories",
                            "gender": "Male",
                            "date_of_birth": "1995-04-18",
                            "nationality": "Pakistani",
                            "job_sector": "Private"
                        },
                        "order_info": [{
                            "item_code": "ITM-00001",
                            "parts": "1",
                            "on_installments": "Yes",
                            "installments_terms": "3month"
                        }]
                    }
            return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "This API endpoint requires a POST request with the following structure in the request body:", {
                "sample_request": sample_request
            })
        else:
            # Validate user_info and customer_info parameters
            user_info = kwargs.get('user_info')
            customer_info = kwargs.get('customer_info')
            order_info = kwargs.get('order_info')
            payment_info = kwargs.get('payment_info')

            if not user_info or not isinstance(user_info, dict) or not customer_info or not isinstance(customer_info, dict):
                return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Invalid data format. Please provide user_info and customer_info as dictionaries.")

            # Extract user information from user_info dictionary
            email = user_info.get('email')
            first_name = user_info.get('first_name')
            last_name = user_info.get('last_name', '')

            # Validate email address
            if not email or not frappe.utils.validate_email_address(email):
                return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Please provide a valid email address.")

            # Check if the user already exists
            if frappe.db.exists("User", {"email": email}):
                user = frappe.get_doc("User", {"email": email})
                if frappe.db.exists("Customer", {"email": email, "account_manager": email}):
                    customer = frappe.get_doc("Customer", {"email": email, "account_manager": email})
                    if customer:
                        if customer.disabled:
                            return _create_response(HTTPStatus.UNAUTHORIZED, "error", "Customer with this email and information is already registered but disabled.")
                        else:
                            if not order_info or not isinstance(order_info, list):
                                return _create_response(HTTPStatus.BAD_REQUEST, "error", "Please provide valid order information.")
                            
                            if not payment_info or not isinstance(payment_info, dict):
                                return _create_response(HTTPStatus.BAD_REQUEST, "error", "Please provide valid payment information.")
                            
                            payment_method = payment_info.get("payment_option")
                            if not payment_method:
                                return _create_response(HTTPStatus.BAD_REQUEST, "error", "Please provide valid payment option.")

                            create_order(email, order_info,payment_info)
                else:
                    # Create a new customer based on customer_info details
                    customer = {
                        "doctype": "Customer",
                        "email": email,
                        "account_manager": email,
                        "first_name": frappe.utils.escape_html(first_name),
                        "last_name": frappe.utils.escape_html(last_name),
                        "disabled": 0,
                        **{key: value for key, value in customer_info.items()}  # Map all fields dynamically
                    }
                    customer_doc = frappe.get_doc(customer)
                    customer_doc.flags.ignore_permissions = True
                    customer_doc.insert()
                    create_order(email, order_info,payment_info)
            else:
                return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", 'No registered user against this email')

    except Exception as e:
        return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", 'An error occurred: {}'.format(str(e)))

@frappe.whitelist(allow_guest=True)
def fetch_sales_history(**kwargs):
	try:
		if frappe.request.method == "GET":
			email = kwargs.get('email')
			if not email:
				return _create_response(HTTPStatus.NOT_FOUND, "error", "No buyer information. Please send buyer/customer's email")

			customer_name = frappe.db.get_value("Customer", {"account_manager": email})
			if not customer_name:
				return _create_response(HTTPStatus.NOT_FOUND, "error", "No customer created against this email")

			sales_invoices = frappe.get_all("Sales Invoice",
											filters={"customer": customer_name,"docstatus":1},
											fields=["name", "posting_date", "grand_total"],
									order_by="posting_date")
			
					
			sales_order = frappe.get_all("Sales Order",
											filters={"customer": customer_name,"docstatus":1},
											fields=["name", "transaction_date", "grand_total"],
									order_by="transaction_date")

			result = []
			for invoice in sales_order:
				invoice_name = invoice.get('name')
				payment_entries = frappe.get_all("Payment Entry Reference",
												filters={"reference_doctype": "Sales Order", "reference_name": invoice_name},
												fields=["total_amount", "outstanding_amount", "allocated_amount","parent"])
				package_name = frappe.db.get_value("Sales Order Item",{"parent": invoice_name},"package_name")

				total = frappe.db.sql(f"""SELECT IFNULL(SUM(paid_amount),0) as paid_amount FROM `tabPayment Entry` 
										WHERE name in (SELECT parent FROM `tabPayment Entry Reference` 
									WHERE reference_name = '{invoice_name}')""",as_dict=1)[0]
				if total:
					paid_amount = total.paid_amount if total.paid_amount else 0					

				payment_status = []
				for term in payment_entries:
					posting_date = frappe.get_value("Payment Entry",{"name": term.parent},
											"posting_date")


					paid_status = "Paid" if term.get('allocated_amount', 0) >= term.get('outstanding_amount', 0) else "Not Paid"
					payment_status.append({
						"due_date": posting_date,
						"payment_amount": term.get('total_amount'),
						"paid_amount": term.get('allocated_amount'),
						"outstanding_amount": term.get('outstanding_amount'),
						"paid_status": paid_status,
						"package_name": package_name
					})
				# if not frappe.db.exists("Sales Invoice Item",{"sales_order",invoice_name}):
				result.append({
					"invoice_name": invoice_name,
					"posting_date": invoice.get('transaction_date'),
					"grand_total": invoice.get('grand_total'),
					"payment_terms": payment_status,
					"paid_amount":paid_amount,
					"paid_status": paid_status,
					"package_name": package_name
				})
			# for invoice in sales_invoices:
			# 	invoice_name = invoice.get('name')
			# 	payment_entries = frappe.get_all("Payment Entry Reference",
			# 									filters={"reference_doctype": "Sales Invoice", "reference_name": invoice_name},
			# 									fields=["total_amount", "outstanding_amount", "allocated_amount","parent"])
			# 	total = frappe.db.sql(f"""SELECT IFNULL(SUM(paid_amount),0) as paid_amount FROM `tabPayment Entry` 
			# 							WHERE name in (SELECT parent FROM `tabPayment Entry Reference` 
			# 						WHERE reference_name = '{invoice_name}')""",as_dict=1)[0]
			# 	if total:
			# 		paid_amount = total.paid_amount if total.paid_amount else 0				

			# 	payment_status = []
			# 	for term in payment_entries:
			# 		posting_date = frappe.get_value("Payment Entry",{"name": term.parent},"posting_date")
			# 		paid_status = "Paid" if term.get('allocated_amount', 0) >= term.get('outstanding_amount', 0) else "Not Paid"
			# 		payment_status.append({
			# 			"due_date": posting_date,
			# 			"payment_amount": term.get('total_amount'),
			# 			"paid_amount": term.get('allocated_amount'),
			# 			"outstanding_amount": term.get('outstanding_amount'),
			# 			"paid_status": paid_status,
			# 		"paid_amount":paid_amount
			# 		})

			# 	result.append({
			# 		"invoice_name": invoice_name,
			# 		"posting_date": invoice.get('posting_date'),
			# 		"grand_total": invoice.get('grand_total'),
			# 		"payment_terms": payment_status
			# 	})
				
			return _create_response(HTTPStatus.OK, "success", "Sales history fetched successfully",{"sales_invoices":result})

		elif frappe.request.method == "POST":
			sample_request = {
					"email": "example@example.com"
			}
			
			return _create_response(HTTPStatus.BAD_REQUEST, "error", "Please send a GET request with the following sample body: ",{"sameple":sample_request} )
	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", f'Bad request, An error occurred: {str(e)}')

@frappe.whitelist(allow_guest=True)
def make_payment_entry(**kwargs):
	try:
		if frappe.request.method != "POST":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")

		email = kwargs.get('email')
		payment_amount = kwargs.get('payment_amount')  # The amount to be paid
		order_name = kwargs.get('order_name')  # The name of the sales order to link the payment to
		paid_via = kwargs.get('paid_via')
		if not email or not payment_amount or not order_name:
			return _create_response(HTTPStatus.BAD_REQUEST, "error", "Please provide 'email', 'payment_amount', and 'order_name' parameters.")

		# Assuming you have some logic to fetch the customer based on the email
		customer = frappe.get_doc("Customer", {"email": email, "account_manager": email})

		if not customer:
			return _create_response(HTTPStatus.NOT_FOUND, "error", "Customer not found.")

		# Create a new Payment Entry document
		payment_entry = frappe.get_doc({
			"doctype": "Payment Entry",
			"payment_type": "Receive",
			"party_type": "Customer",
			"party": customer.name,
			"posting_date": frappe.utils.today(),
			"paid_amount": payment_amount,
			"reference_doctype": "Sales Order",
			"received_amount": payment_amount,
			"reference_name": order_name,
			"mode_of_payment": paid_via,
			"paid_to":"Cash - E",
			"references": [
				{
					"reference_doctype": "Sales Order",
					"reference_name": order_name,
					"allocated_amount": payment_amount
				}
			]
		})

		# Insert the new payment entry into the database
		payment_entry.flags.ignore_permissions = True
		payment_entry.insert(ignore_permissions=True)
		payment_entry.submit()

		return _create_response(HTTPStatus.OK, "success", "Payment entry created successfully.")

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def update_customer(**kwargs):
	try:
		if frappe.request.method != "PUT":
			sample_payload = {
				"customer_info":{
					"email":"mavee.shah@icloud.com",
					"first_name":"mavee"
				}
			}
			return _create_response(HTTPStatus.BAD_REQUEST, "error", sample_payload)

		try:
			cus_info = kwargs.get("customer_info")
			customer = frappe.get_doc("Customer", {"account_manager": cus_info.get("email")})
			if customer:
				# Update the customer document with the payload directly
				customer.update(cus_info)
				customer.save(ignore_permissions=True)
				frappe.db.commit()
				
				return _create_response(HTTPStatus.OK, "success", "Customer info updated successfully")
			else:
				return _create_response(HTTPStatus.NOT_FOUND, "error", "Customer not found")
		except Exception as e:
			return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))


	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def breeder_registration(**kwargs):
	try:
		if frappe.request.method != "POST":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", _("Method Not Allowed"))
		breeder_info = kwargs.get("breeder_info")

		if not breeder_info:
			return _create_response(HTTPStatus.BAD_REQUEST, "error", _("Please send breeder_info."))
		email = breeder_info['email']
		if is_signup_disabled():
			return _create_response(HTTPStatus.FORBIDDEN, "error", _("Sign Up is disabled"))

		if not is_valid_email(email):
			return _create_response(HTTPStatus.BAD_REQUEST, "error", _("Invalid email format"))

		user = frappe.db.get("User", {"email": email})
		if user:
			if user.enabled:
				return _create_response(HTTPStatus.CONFLICT, "error", _(f"This email is not available. '{email}'. Please use another"))
			else:
				return _create_response(HTTPStatus.CONFLICT, "error", _(f"This email is not available. '{email}'. Please use another"))
		else:
			if frappe.db.exists("Breeder Applicant",{"email":breeder_info["email"],"docstatus":0}):
				return _create_response(HTTPStatus.CONFLICT, "error", _("Your application is already under process."))
			if frappe.db.exists("Breeder Applicant",{"email":breeder_info["email"],"docstatus":1}) \
				or frappe.db.exists("Breeder",{"username":breeder_info["email"]}):
				return _create_response(HTTPStatus.CONFLICT, "error", _("A user with same email is already registered as breeder."))
			# Handle image attachment
			image_data = breeder_info.pop("image", None)
			if image_data:
				file_name = f"{email}_ProfilePicture.jpg"  # Adjust the filename as needed
				save_image_as_attachment(file_name, image_data)

			breeder_application = frappe.new_doc("Breeder Applicant")
			breeder_application.flags.ignore_permissions = True
			breeder_application.update(breeder_info)
			breeder_application.insert()
			
			return _create_response(HTTPStatus.OK, "success", "Your application has been received. You'll receive confirmation email when an admin approves.")

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred while processing the application: {}".format(str(e)))
		
@frappe.whitelist(allow_guest=True)
def feedlot_registration(**kwargs):
	try:
		if frappe.request.method != "POST":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", _("Method Not Allowed"))
		
		feedlot_info = kwargs.get("feedlot_info")
		if not feedlot_info:
			return _create_response(HTTPStatus.BAD_REQUEST, "error", _("Please send feedlot_info."))
		feedlot_application = frappe.new_doc("Feedlot Applicant")
		feedlot_application.flags.ignore_permissions = True
		feedlot_application.update(feedlot_info)
		feedlot_application.insert()
		
		return _create_response(HTTPStatus.OK, "success", "Your application has been received. You'll receive confirmation email when an admin approves.")

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred while processing the application: {}".format(str(e)))
		
@frappe.whitelist(allow_guest=True)
def get_master_data(**kwargs):
	try:
		if frappe.request.method != "GET":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", _("Method Not Allowed"))

		master_data = {}
		salutation_list = frappe.db.get_all("Salutation",pluck='name')
		nationality_list = frappe.db.get_all("Nationality",pluck='name')
		gender_list = frappe.db.get_all("Gender",pluck='name')
		marital_status_list = frappe.db.get_all("Marital Status",pluck='name')
		job_sector_list = frappe.db.get_all("Job Sector",pluck='name')
		bank_list = frappe.db.get_all("Bank",pluck='name')

		master_data = {
					"salutation_list" : salutation_list,
					"nationality_list" : nationality_list,
					"gender_list" : gender_list,
					"marital_status_list" : marital_status_list,
					"job_sector_list" : job_sector_list,
					"bank_list" : bank_list,
		}
		return _create_response(HTTPStatus.OK, "success","", {"master_data": master_data})

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred while processing the application: {}".format(str(e)))
	
@frappe.whitelist(allow_guest=True)
def get_breeder_profile(**kwargs):
	try:
		if frappe.request.method != "GET":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", _("Method Not Allowed"))
		email = kwargs.get('email')
		if not email:
			return _create_response(HTTPStatus.NOT_FOUND, "error", "No user information. Please send user's email")

		if not frappe.db.exists("Breeder",{"username":email}):
			return _create_response(HTTPStatus.NOT_FOUND, "error", "No breeder against this email.")

		user = frappe.get_doc('User', email)
		response_dict = {}
		if user.role_profile_name == "Breeder":
			exclude_fields = ["creation", "modified","amended_from", "modified_by", "owner","docstatus","idx","naming_series","_user_tags","_comments","_assign","_liked_by","_seen"]
			breeder_fields = [field.fieldname for field in frappe.get_meta("Breeder").fields if field.fieldname not in exclude_fields and field.fieldtype not in ["Tab Break","Section Break","Column Break"]]
			breeder_fields.append("name")
			breeder_prof = frappe.get_all("Breeder",
											filters={"username": email},
											fields=[field for field in breeder_fields])
			response_dict["role"] = "Breeder"
			response_dict["profile_info"] = breeder_prof
			return _create_response(HTTPStatus.OK, "success","Success", {"user_info" :response_dict})

		# exclude_fields = ["creation", "modified","amended_from", "modified_by", "owner","docstatus","idx","naming_series","_user_tags","_comments","_assign","_liked_by","_seen"]
		# breeder_fields = [field for field in frappe.get_meta("Breeder").fields if field.fieldname not in exclude_fields and field.fieldtype not in ["Tab Break","Section Break","Column Break"]]
		# breeder_prof = frappe.get_all("Breeder",
		# 								filters={"username": email},
		# 								fields=[field.fieldname for field in breeder_fields])
				
		# return _create_response(HTTPStatus.OK, "success","", {"breeder": breeder_prof})

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred while processing the application: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def put_breeder_profile(**kwargs):
	try:
		if frappe.request.method != "PUT":
			sample_payload = {
				"breeder_info": {
					"email": "johndoe@example.com",
					"name": "Updated Breeder Name"
				}
			}
			return _create_response(HTTPStatus.BAD_REQUEST, "error", sample_payload)

		try:
			breeder_info = kwargs.get("breeder_info")
			email = breeder_info.get("email")

			# Check if the breeder exists
			if not frappe.db.exists("Breeder", {"username": email}):
				return _create_response(HTTPStatus.NOT_FOUND, "error", "Breeder not found")

			# Update the breeder document with the payload directly
			frappe.db.set_value("Breeder", {"username": email}, breeder_info)
			frappe.db.commit()

			return _create_response(HTTPStatus.OK, "success", "Breeder profile updated successfully")

		except Exception as e:
			return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def get_feedlot_profile(**kwargs):
	try:
		if frappe.request.method != "GET":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", _("Method Not Allowed"))
		email = kwargs.get('email')
		if not email:
			return _create_response(HTTPStatus.NOT_FOUND, "error", "No user information. Please send user's email")

		if not frappe.db.exists("Feedlot",{"username":email}):
			return _create_response(HTTPStatus.NOT_FOUND, "error", "No feedlot against this email.")

		user = frappe.get_doc('User', email)
		response_dict = {}
		if user.role_profile_name == "Feedlot":
			exclude_fields = ["creation", "modified","amended_from", "modified_by", "owner","docstatus","idx","naming_series","_user_tags","_comments","_assign","_liked_by","_seen"]
			feedlot_fields = [field.fieldname for field in frappe.get_meta("Feedlot").fields if field.fieldname not in exclude_fields and field.fieldtype not in ["Tab Break","Section Break","Column Break"]]
			feedlot_fields.append("name")
			feedlot_prof = frappe.get_all("Feedlot",
											filters={"username": email},
											fields=[field for field in feedlot_fields])
			name = feedlot_prof[0]["breeder_id"]
			feed_id = feedlot_prof[0]["name"]
			feedlot_prof[0]["name"] = name
			feedlot_prof[0]["feedlot_id"] = feed_id
			response_dict["role"] = "Feedlot"
			response_dict["profile_info"] = feedlot_prof
			
			return _create_response(HTTPStatus.OK, "success","Feedlot profile updated successfully", {"user_info" :response_dict})
		# exclude_fields = ["creation", "modified", "modified_by", "owner","docstatus","idx","naming_series","_user_tags","_comments","_assign","_liked_by","_seen"]
		# feedlot_fields = [field for field in frappe.get_meta("Feedlot").fields if field.fieldname not in exclude_fields and field.fieldtype not in ["Tab Break","Section Break","Column Break"]]
		# feedlot_prof = frappe.get_all("Feedlot",
		# 								filters={"username": email},
		# 								fields=[field.fieldname for field in feedlot_fields])
		# return _create_response(HTTPStatus.OK, "success","", {"feedlot": feedlot_prof})

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred while processing the application: {}".format(str(e)))
	
@frappe.whitelist(allow_guest=True)
def put_feedlot_profile(**kwargs):
	try:
		if frappe.request.method != "PUT":
			sample_payload = {
				"feedlot_info": {
					"email": "example@feedlot.com",
					"name": "Updated Feedlot Name"
				}
			}
			return _create_response(HTTPStatus.BAD_REQUEST, "error", sample_payload)

		try:
			feedlot_info = kwargs.get("feedlot_info")
			email = feedlot_info.get("email")

			# Check if the feedlot exists
			if not frappe.db.exists("Feedlot", {"username": email}):
				return _create_response(HTTPStatus.NOT_FOUND, "error", "Feedlot not found")

			# Define a list of fields to pop from feedlot_info
			fields_to_pop = ["name", "breeder_id", "username","email","feedlot_id"]  # Replace with the actual field names you want to remove

			# Pop the specified fields from feedlot_info
			for field in fields_to_pop:
				feedlot_info.pop(field, None)
			# Update the feedlot document with the payload directly
			frappe.db.set_value("Feedlot", {"username": email}, feedlot_info)
			frappe.db.commit()

			return _create_response(HTTPStatus.OK, "success", "Feedlot profile updated successfully")

		except Exception as e:
			return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def verify_breeder(**kwargs):
    try:
        if frappe.request.method != "PUT":
            sample_payload = {
                "breeder_info": {
                    "email": "example@breeder.com",
                }
            }
            return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error","", {"sample":sample_payload})

        try:
            breeder_info = kwargs.get("breeder_info")
            email = breeder_info.get("email")

            # Check if the feedlot exists
            if not frappe.db.exists("Breeder", {"username": email}):
                return _create_response(HTTPStatus.NOT_FOUND, "error", "Breeder not found")

            # Tick the checkbox to verify the breeder
            frappe.db.set_value("Breeder", {"username": email}, "verified" , 1)

            frappe.db.commit()

            return _create_response(HTTPStatus.OK, "success", "Breeder verified")

        except Exception as e:
            return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

    except Exception as e:
        return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def verify_feedlot(**kwargs):
    try:
        if frappe.request.method != "PUT":
            sample_payload = {
                "feedlot_info": {
                    "email": "example@feedlot.com",
                }
            }
            return _create_response(HTTPStatus.BAD_REQUEST, "error", sample_payload)

        try:
            feedlot_info = kwargs.get("feedlot_info")
            email = feedlot_info.get("email")

            # Check if the feedlot exists
            if not frappe.db.exists("Feedlot", {"username": email}):
                return _create_response(HTTPStatus.NOT_FOUND, "error", "Feedlot not found")

            # Tick the checkbox to verify the feedlot
            frappe.db.set_value("Feedlot", {"username": email}, "verified" , 1)

            frappe.db.commit()

            return _create_response(HTTPStatus.OK, "success", "Feedlot verified")

        except Exception as e:
            return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

    except Exception as e:
        return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def apply_for_e_pawah(**kwargs):
	try:
		if frappe.request.method != "POST":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", _("Method Not Allowed"))
		
		applicant_info = kwargs.get("applicant_info")
		if not applicant_info:
			return _create_response(HTTPStatus.BAD_REQUEST, "error", _("Please send applicant_info."))
		
		role = kwargs.get("role")
		applicant_info = kwargs.get("applicant_info")
		breeder_id = applicant_info.get("breeder_id")

		# Check if the feedlot/breeder exists
		# if role == "Breeder":
		if not frappe.db.exists("Breeder", {"name": breeder_id}):
			return _create_response(HTTPStatus.NOT_FOUND, "error", "Breeder/Feedlot not found")
		# if role == "Feedlot":
		# 	if not frappe.db.exists("Feedlot",{"name":breeder_id}):
		# 		return _create_response(HTTPStatus.NOT_FOUND, "error", "Feedlot not found")
		# 	else:
		# 		applicant_info["breeder_id"] = frappe.db.get_value("Feedlot",{"name":breeder_id},"breeder_id")

		breeder_id = applicant_info.get("breeder_id")
		if frappe.db.exists("E Pawah Application",{"breeder_id":breeder_id,"docstatus":0}):
			return _create_response(HTTPStatus.CONFLICT, "error", _("Your application is already under process."))
		if frappe.db.exists("E Pawah Application",{"breeder_id":breeder_id,"docstatus":1}):
			return _create_response(HTTPStatus.CONFLICT, "error", _(f"A breeder/feedlot with same id {breeder_id} is already registered under e pawah."))
		
		e_pawah_application = frappe.new_doc("E Pawah Application")
		e_pawah_application.flags.ignore_permissions = True
		e_pawah_application.update(applicant_info)
		e_pawah_application.insert()
		

		return _create_response(HTTPStatus.OK, "success", "Your application has been received. You'll receive confirmation email when an admin approves.")

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred while processing the application: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def get_e_pawah_applications(**kwargs):
	try:
		if frappe.request.method != "GET":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", _("Method Not Allowed"))
		email = kwargs.get('email')
		if not email:
			return _create_response(HTTPStatus.NOT_FOUND, "error", "No user information. Please send user's email")

		if not frappe.db.exists("E Pawah Application",{"username":email}):
			return _create_response(HTTPStatus.NOT_FOUND, "error", "No Application against this breeder/feedlot.")


		if frappe.db.exists("E Pawah Application",{"username":email,"docstatus":2}) :
			if not (frappe.db.exists("E Pawah Application",{"username":email,"docstatus":1}) or frappe.db.exists("E Pawah Application",{"username":email,"docstatus":0})):

				return _create_response(HTTPStatus.CONFLICT, "error", "Application against this breeder/feedlot has been cancelled.")
		
		application = frappe.db.get_value("E Pawah Application",{"username":email},"name")
		response_dict = frappe.get_doc("E Pawah Application",application)

		return _create_response(HTTPStatus.OK, "success","Success", {"application_info" :response_dict.as_dict()})

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred while processing the application: {}".format(str(e)))

@frappe.whitelist(allow_guest=True)
def create_ruminant(**kwargs):
    try:
        if frappe.request.method != "POST":
            return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")

        ruminant_data = kwargs.get("ruminant_data")

        if not ruminant_data:
            return _create_response(HTTPStatus.BAD_REQUEST, "error", "Ruminant data is required")

        # Validate the ruminant_data here
        # Implement validation logic to ensure the data is correct before creating the record

        # Create the Ruminant document
        ruminant = frappe.new_doc("Ruminant")
        ruminant.update(ruminant_data)
        ruminant.insert(ignore_permissions=True)

        return _create_response(HTTPStatus.CREATED, "success", "Ruminant created successfully")

    except Exception as e:
        return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))


@frappe.whitelist(allow_guest=True)
def get_ruminant(breeder_id,from_date=None,to_date=None,ruminant_status=None):
	try:
		if frappe.request.method != "GET":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")
		filters = {"breeder_id": breeder_id}
		if from_date:
			filters["creation"] = [">", from_date]
		if to_date:
			filters["creation"] = ["<", to_date]
		if ruminant_status:
			filters["physical_status_goodbad_for_qurban"] = ["=", ruminant_status]

		ruminants = frappe.get_all("Ruminant", filters=filters)

		if not ruminants:
			return _create_response(HTTPStatus.NOT_FOUND, "error", "Ruminant not found")
		ruminant_data = []
		for ruminant in ruminants:
			ruminant_data.append(frappe.get_doc("Ruminant",ruminant.name).as_dict())

		return _create_response(HTTPStatus.OK, "success", "Ruminant retrieved successfully", {"ruminants":ruminant_data})

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))


@frappe.whitelist(allow_guest=True)
def get_ruminant_details(ruminant_id):
	try:
		if frappe.request.method != "GET":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")
		ruminant = frappe.get_doc("Ruminant", ruminant_id)

		if not ruminant:
			return _create_response(HTTPStatus.NOT_FOUND, "error", "Ruminant not found")

		return _create_response(HTTPStatus.OK, "success", "Ruminant retrieved successfully", {"ruminants":ruminant.as_dict()})

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))


@frappe.whitelist(allow_guest=True)
def update_ruminant(ruminant_id, **kwargs):
	try:
		if frappe.request.method != "PUT":
			return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")

		ruminant = frappe.get_doc("Ruminant", ruminant_id)

		if not ruminant:
			return _create_response(HTTPStatus.NOT_FOUND, "error", "Ruminant not found")

		ruminant_data = kwargs.get("ruminant_data")

		if not ruminant_data:
			return _create_response(HTTPStatus.BAD_REQUEST, "error", "Ruminant data is required for update")

		# Validate the ruminant_data here
		# Implement validation logic to ensure the data is correct before updating the record
		# Define a list of fields to pop from feedlot_info
		fields_to_pop = ["name", "breeder_id"]  # Replace with the actual field names you want to remove

		# Pop the specified fields from feedlot_info
		for field in fields_to_pop:
			ruminant_data.pop(field, None)
		# Update the Ruminant document
		ruminant.update(ruminant_data)
		ruminant.save(ignore_permissions=True)

		return _create_response(HTTPStatus.OK, "success", "Ruminant updated successfully")

	except Exception as e:
		return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))


@frappe.whitelist(allow_guest=True)
def delete_ruminant(ruminant_id):
    try:
        if frappe.request.method != "DELETE":
            return _create_response(HTTPStatus.METHOD_NOT_ALLOWED, "error", "Method Not Allowed")

        ruminant = frappe.get_doc("Ruminant", ruminant_id)

        if not ruminant:
            return _create_response(HTTPStatus.NOT_FOUND, "error", "Ruminant not found")

        # Delete the Ruminant document
        ruminant.delete()

        return _create_response(HTTPStatus.NO_CONTENT, "success", "Ruminant deleted successfully")

    except Exception as e:
        return _create_response(HTTPStatus.INTERNAL_SERVER_ERROR, "error", "An error occurred: {}".format(str(e)))
