module XssTerminate
  def self.included(base)
    base.extend(ClassMethods)
    # sets up default of stripping tags for all fields
    base.send(:xss_terminate)
  end

  module ClassMethods
    def xss_terminate(options = {})
      before_validation :sanitize_fields, :sanitize_methods

      write_inheritable_attribute(:xss_terminate_options, {
        :except => (options[:except] || []),
        :html5lib_sanitize => (options[:html5lib_sanitize] || []),
        :sanitize => (options[:sanitize] || []),
        :sanitize_methods => (options[:sanitize_methods] || [])
      })
      
      class_inheritable_reader :xss_terminate_options
      
      include XssTerminate::InstanceMethods
    end
  end
  
  module InstanceMethods

    def sanitize_fields
      # fix a bug with Rails internal AR::Base models that get loaded before
      # the plugin, like CGI::Sessions::ActiveRecordStore::Session
      return if xss_terminate_options.nil?
      
      self.class.columns.each do |column|
        next unless (column.type == :string || column.type == :text)
        
        field = column.name.to_sym
        value = self[field]

        next if value.nil? || !value.is_a?(String)
        
        if xss_terminate_options[:except].include?(field)
          next
        elsif xss_terminate_options[:html5lib_sanitize].include?(field)
          self[field] = HTML5libSanitize.new.sanitize_html(value)
        elsif xss_terminate_options[:sanitize].include?(field)
          self[field] = RailsSanitize.white_list_sanitizer.sanitize(value)
        else
          self[field] = RailsSanitize.full_sanitizer.sanitize(value)
        end
      end
      
    end

    def sanitize_methods
      unless xss_terminate_options[:sanitize_methods].blank?
        xss_terminate_options[:sanitize_methods].each do |method|
          value = send(method)
          next unless value.blank? || value.is_a?(String)
          
          if xss_terminate_options[:html5lib_sanitize].include?(method)
            send("#{method}=", HTML5libSanitize.new.sanitize_html(value))
          elsif xss_terminate_options[:sanitize].include?(method)
            send("#{method}=", RailsSanitize.white_list_sanitizer.sanitize(value))
          else
            send("#{method}=", RailsSanitize.full_sanitizer.sanitize(value))
          end
        end
      end
    end
  end
end
