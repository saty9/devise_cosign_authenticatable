
# Rails 3, 4

ActionDispatch::Routing::Mapper.class_eval do
  protected
  def devise_cosign_authenticatable(mapping, controllers)
    sign_out_via = (Devise.respond_to?(:sign_out_via) && Devise.sign_out_via) || [:get, :post]

    # service endpoint for CoSign server
    get "service", :to => "#{controllers[:cosign_sessions]}#service", :as => "service"
    post "service", :to => "#{controllers[:cosign_sessions]}#single_sign_out", :as => "single_sign_out"

    resource :session, :only => [], :controller => controllers[:cosign_sessions], :path => "" do
      get :new_cosign, :path => mapping.path_names[:sign_in], :as => "new_cosign"
      get :unregistered_cosign
      post :create_cosign, :path => mapping.path_names[:sign_in]
      match :destroy_cosign, :path => mapping.path_names[:sign_out], :as => "destroy_cosign", :via => sign_out_via
    end
  end
end
