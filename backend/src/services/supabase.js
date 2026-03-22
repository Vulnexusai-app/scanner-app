const { createClient } = require('@supabase/supabase-js')

const supabase = createClient(
  process.env.SUPABASE_URL || 'https://example.supabase.co',
  process.env.SUPABASE_SERVICE_KEY || 'dummy_key'
)

module.exports = supabase
