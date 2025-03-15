
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # Fetch the profile of the currently logged-in user
    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()

    if request.method == 'POST':
        # Get form data
        bio = request.form.get('bio', '').strip()
        interests = request.form.get('interests', '').strip()
        profile_picture = request.files.get('profile_picture')

        # If the profile doesn't exist, create one
        if not user_profile:
            user_profile = UserProfile(user_id=current_user.id, bio=bio, interests=interests)
            db.session.add(user_profile)
        else:
            # Update profile fields
            user_profile.bio = bio
            user_profile.interests = interests

        # Handle profile picture upload
        if profile_picture and allowed_file(profile_picture.filename):
            # Delete old profile picture if it exists
            if user_profile.profile_picture:
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], user_profile.profile_picture)
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)

            # Save new profile picture
            filename = secure_filename(f"user_{current_user.id}_profile_picture.{profile_picture.filename.rsplit('.', 1)[1].lower()}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(filepath)
            user_profile.profile_picture = filename  # Save file path in the database

        # Save changes to the database
        db.session.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    # Render the profile template with the current user's profile data
    return render_template('profile.html', profile=user_profile)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    bio = data.get('bio', '').strip()
    interests = data.get('interests', '').strip()

    user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()
    if not user_profile:
        user_profile = UserProfile(user_id=current_user.id, bio=bio, interests=interests)
        db.session.add(user_profile)
    else:
        user_profile.bio = bio
        user_profile.interests = interests

    db.session.commit()
    return jsonify({"success": True})

@app.route('/update_profile_picture', methods=['POST'])
@login_required
def update_profile_picture():
    if 'profile_picture' not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"})

    profile_picture = request.files['profile_picture']
    if profile_picture and allowed_file(profile_picture.filename):
        filename = secure_filename(f"user_{current_user.id}_profile_picture.{profile_picture.filename.rsplit('.', 1)[1].lower()}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        profile_picture.save(filepath)

        user_profile = UserProfile.query.filter_by(user_id=current_user.id).first()
        if not user_profile:
            user_profile = UserProfile(user_id=current_user.id)
            db.session.add(user_profile)
        user_profile.profile_picture = filename
        db.session.commit()

        return jsonify({"success": True, "profile_picture_url": url_for('static', filename=f"uploads/{filename}")})

    return jsonify({"success": False, "error": "Invalid file type"})
