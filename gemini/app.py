import streamlit as st
from google import genai
from google.genai import types

# ---------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------
st.set_page_config(page_title="Gemini Chat UI", page_icon="✨", layout="wide")
st.title("✨ Gemini Complete UI")
st.markdown("Enter your API key in the sidebar to securely fetch your available models and start chatting.")

# ---------------------------------------------------------
# Sidebar: Configuration & API Key Input
# ---------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Configuration")
    api_key = st.text_input("Gemini API Key", type="password", help="Get this from Google AI Studio")
    
    selected_model = None
    temperature = 0.7
    system_instruction = ""
    
    if api_key:
        try:
            # Initialize the modern Google GenAI client
            client = genai.Client(api_key=api_key)
            
            st.caption("Fetching available models...")
            # Fetch and format the list of available models for this key
            available_models = []
            for m in client.models.list():
                # Extract the model name properly
                name = getattr(m, 'name', str(m))
                
                # Filter to only show base models and gemini models (hides system/legacy junk)
                if "gemini" in name.lower():
                    # Strip 'models/' prefix if present for a cleaner UI
                    clean_name = name.replace("models/", "")
                    available_models.append(clean_name)
                    
            # Deduplicate and sort
            available_models = sorted(list(set(available_models)))
            
            if available_models:
                # Default to a highly capable flash model if available
                default_index = 0
                if "gemini-2.5-flash" in available_models:
                    default_index = available_models.index("gemini-2.5-flash")
                    
                selected_model = st.selectbox("Select a Model", available_models, index=default_index)
            else:
                selected_model = st.text_input("Enter Model Name Manually", value="gemini-2.5-flash")
                
            st.divider()
            st.subheader("Model Parameters")
            system_instruction = st.text_area("System Instruction", help="Give the AI a persona, rule, or specific behavior.")
            temperature = st.slider("Temperature", min_value=0.0, max_value=2.0, value=0.7, step=0.1, 
                                    help="Higher values make output more random, lower values make it more deterministic.")
            
            if st.button("Clear Chat History"):
                st.session_state.messages = []
                st.rerun()
                
        except Exception as e:
            st.error(f"Error validating API Key: {e}")
    else:
        st.info("👈 Awaiting API Key to load models.")

# ---------------------------------------------------------
# Main Chat Interface
# ---------------------------------------------------------
if api_key and selected_model:
    # Initialize chat history in session state
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Render existing conversation
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Accept user input
    if prompt := st.chat_input(f"Message {selected_model}..."):
        
        # Append and display the user's message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Convert Streamlit history into GenAI SDK Content types
        contents = []
        for msg in st.session_state.messages:
            # Map 'assistant' to the SDK's expected 'model' role
            role = "user" if msg["role"] == "user" else "model"
            contents.append(
                types.Content(role=role, parts=[types.Part.from_text(text=msg["content"])])
            )
            
        # Stream the assistant's response
        with st.chat_message("assistant"):
            response_placeholder = st.empty()
            full_response = ""
            
            try:
                # Build configuration
                config = types.GenerateContentConfig(temperature=temperature)
                if system_instruction.strip():
                    config.system_instruction = system_instruction
                
                # Use generate_content_stream for a typing-effect UI
                response_stream = client.models.generate_content_stream(
                    model=selected_model,
                    contents=contents,
                    config=config
                )
                
                for chunk in response_stream:
                    if chunk.text:
                        full_response += chunk.text
                        response_placeholder.markdown(full_response + "▌")
                
                # Drop the cursor block and finalize the text
                response_placeholder.markdown(full_response)
                
                # Save the assistant's response to history
                st.session_state.messages.append({"role": "assistant", "content": full_response})
                
            except Exception as e:
                st.error(f"An API error occurred: {e}")