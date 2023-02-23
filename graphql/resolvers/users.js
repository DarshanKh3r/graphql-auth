const Message = require('../../models/User');
const { ApolloError } = require('apollo-server-errors');
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");

module.exports = {
    Mutation: {
        async registerUser(_, {registerInput: {username, email, password} }){
            //See if an old user exists with email attempting to register
            const oldUser = await user.findOne({ email });

            if(oldUser){
                throw new ApolloError('A user is already registered with the email' + email, 'USER_ALREADY_EXISTS');                
            }


            //throw error if that user exists

            // encrypt password
            var encryptedPassword = await bcrypt.hash(password, 10);

            //build our mongoose model
            const newUser = new User ({
                username: username,
                email: email.toLowerCase(),
                password: encryptedPassword
            })
            // create our JWT (attach to user model)
            const token = jwt.sign(
                { user_id: newUser._id, email },
                "UNSAFE_STRING",
                {
                    expiresIn: "2h"
                }
            );

            newUser.token = token;


            // Save Our User in mongoDB
            const res = await newUser.save();

            return{
                id: res.id,
                ...res._doc
            }

        },
        async loginUser(_, {loginUser : { email, password} }){
            //See if a user exists with the email
            const user = await User.findOne({ email });

            // Check if the entered password equals to the encrypted password
            if (user && (await bcrypt.compare(password, user.password))) {
            //create a new token
                const token = jwt.sign(
                    { user_id: newUser._id, email },
                    "UNSAFE_STRING",
                    {
                        expiresIn: "2h"
                    }
                );
            
                // attach token to user model that we found above
                user.token = token;
                return{
                    id: user.id,
                    ...user._doc
                }
            }
            else{
                throw new ApolloError("Incorrect Password", "INCORRECT_PASSWORD");
            }
            // if user doesn't exist, return error
        }
        
    },
    Query: {
        user: (_, {ID}) => User.findById(ID)
    }
}